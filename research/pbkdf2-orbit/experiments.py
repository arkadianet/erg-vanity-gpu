"""Hypothesis tests for a cheaper exact representation of the PBKDF2 orbit.

Each test either:
  * finds a candidate identity and immediately re-checks it up the model ladder, or
  * records that the identity failed on the stated sample/enumeration.

A failure is a tested negative, not a non-existence proof.
"""

from __future__ import annotations

import hashlib
import hmac as std_hmac
import os
import random
import statistics
import struct
from collections import defaultdict
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from model import (
    Envelope,
    HMAC64_BITLEN,
    LADDER,
    Params,
    SHA512_H,
    compress,
    conventional_budget,
    cost_F,
    hmac64_F_words,
    hmac64_pad_block,
    hmac_midstates,
    instrumented_sha512_compress,
    iv_words,
    orbit_xor,
    pack_state,
    unpack_state,
    verify_full_hmac_against_stdlib,
)
from bdd import bdd_sizes_from_table, compose_table, xor_prefix_table
from symbolic import dag_report, Dag, symbolic_compress, symbolic_pad


ENUM_BITS = 16  # exhaustive functional-graph cutoff
SAMPLE_N = 96
RNG = random.Random(0x50626B64)  # 'Pbkd'


def _bitmask(p: Params) -> int:
    return (1 << p.state_bits) - 1


def _sample_domain(p: Params, n: int) -> List[int]:
    m = _bitmask(p)
    if p.state_bits <= ENUM_BITS:
        n = min(n, 1 << p.state_bits)
        return [RNG.randrange(m + 1) for _ in range(n)]
    return [RNG.getrandbits(p.state_bits) & m for _ in range(n)]


def _all_domain(p: Params) -> range:
    return range(1 << p.state_bits)


def enumerable(p: Params) -> bool:
    return p.state_bits <= ENUM_BITS


# ---------------------------------------------------------------------------
# 0. Self-check
# ---------------------------------------------------------------------------

def exp_selfcheck() -> dict:
    verify_full_hmac_against_stdlib(16)
    # BIP39 test vector via hashlib (independent of repo crypto crate)
    mnemonic = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    ).encode()
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic, b"mnemonic", 2048, dklen=64)
    expect = bytes.fromhex(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
        "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    )
    if seed != expect:
        raise AssertionError("stdlib BIP39 vector mismatch")
    p = Params(w=64, words=8, rounds=80, use_ch_maj=True, use_schedule=True, name="sha512")
    return {
        "hmac_envelope_matches_hashlib": True,
        "bip39_vector_ok": True,
        "sha512_F_cost": cost_F(p).as_dict(),
        "sha512_2048_budget": conventional_budget(p, 2048),
    }


# ---------------------------------------------------------------------------
# 1. Identity scan (pointwise algebraic relations)
# ---------------------------------------------------------------------------

def _affine_gf2(fn: Callable[[int], int], bits: int, samples: Sequence[int]) -> bool:
    """F(x⊕y) ⊕ F(0) == (F(x)⊕F(0)) ⊕ (F(y)⊕F(0)) on the sample + basis."""
    z = fn(0)
    # must include 0 and basis vectors
    pts = list(samples)
    for i in range(bits):
        pts.append(1 << i)
    pts.append(0)
    for a in pts[:24]:
        for b in pts[:24]:
            if (fn(a ^ b) ^ z) != (fn(a) ^ z) ^ (fn(b) ^ z):
                return False
    return True


def _affine_mod(fn: Callable[[int], int], bits: int, samples: Sequence[int]) -> bool:
    """F(x+y) - F(0) == (F(x)-F(0)) + (F(y)-F(0)) (mod 2^bits)."""
    m = (1 << bits) - 1
    z = fn(0)
    pts = list(samples[:20]) + [0, 1, 2, m]
    for a in pts:
        for b in pts:
            left = (fn((a + b) & m) - z) & m
            right = ((fn(a) - z) + (fn(b) - z)) & m
            if left != right:
                return False
    return True


def identity_scan(env: Envelope, samples: Sequence[int], n_iter: int = 8) -> dict:
    p = env.p
    m = _bitmask(p)
    fn = env.F
    hits = {
        "F_eq_id": True,
        "F_eq_not": True,
        "F_xor_x_const": True,
        "F_add_x_const": True,
        "F_involution": True,
        "F2_eq_id": True,
        "F2_eq_F": True,
        "F_xor_x_eq_F2_xor_F": True,  # F(x)⊕x == F(F(x))⊕F(x)  =>  F affine involution-ish
        "dk_eq_xor_endpoints": True,  # DK == U1 ⊕ Un
        "dk_eq_x_xor_Fn": True,
        "dk_eq_0_even_n": True,
        "dk_eq_V_id": True,  # DK == x ⊕ F^n(x)   (n iterates)
        "dk_eq_V_F": True,  # DK == F(x) ⊕ F^{n+1}(x)
    }
    xor_delta = None
    add_delta = None
    for x in samples:
        y = fn(x)
        y2 = fn(y)
        if y != x:
            hits["F_eq_id"] = False
        if y != (x ^ m):
            hits["F_eq_not"] = False
        d = y ^ x
        if xor_delta is None:
            xor_delta = d
        elif d != xor_delta:
            hits["F_xor_x_const"] = False
        ad = (y - x) & m
        if add_delta is None:
            add_delta = ad
        elif ad != add_delta:
            hits["F_add_x_const"] = False
        if fn(y) != x:
            hits["F_involution"] = False
        if y2 != x:
            hits["F2_eq_id"] = False
        if y2 != y:
            hits["F2_eq_F"] = False
        if (y ^ x) != (y2 ^ y):
            hits["F_xor_x_eq_F2_xor_F"] = False

        last, dk = orbit_xor(x, fn, n_iter)
        u1 = y
        if dk != (u1 ^ last):
            hits["dk_eq_xor_endpoints"] = False
        if dk != (x ^ last):
            hits["dk_eq_x_xor_Fn"] = False
            hits["dk_eq_V_id"] = False
        if n_iter % 2 == 0 and dk != 0:
            hits["dk_eq_0_even_n"] = False
        if dk != (u1 ^ fn(last)):
            hits["dk_eq_V_F"] = False

    hits["affine_gf2"] = _affine_gf2(fn, p.state_bits, samples)
    hits["affine_mod2w"] = _affine_mod(fn, p.state_bits, samples)
    # any True (other than the always-false-looking ones) is a candidate
    structural = {k: v for k, v in hits.items() if v}
    return {
        "params": str(p),
        "n_samples": len(samples),
        "n_iter": n_iter,
        "true_identities": structural,
        "all": hits,
    }


# ---------------------------------------------------------------------------
# 2. Functional graph + coboundary (enumerable only)
# ---------------------------------------------------------------------------

def functional_graph(env: Envelope) -> dict:
    p = env.p
    if not enumerable(p):
        return {"params": str(p), "skipped": "state_bits > ENUM_BITS"}
    N = 1 << p.state_bits
    nxt = [env.F(i) for i in range(N)]
    # image size (factorization through a smaller set?)
    image = len(set(nxt))
    # cycles
    seen = [0] * N  # 0 unseen, 1 in stack, 2 done
    cycle_lens = []
    cycle_xors = []
    all_cycles_xor0 = True
    for s in range(N):
        if seen[s]:
            continue
        path = []
        index = {}
        v = s
        while seen[v] == 0:
            seen[v] = 1
            index[v] = len(path)
            path.append(v)
            v = nxt[v]
        if seen[v] == 1:
            cyc = path[index[v] :]
            cx = 0
            for u in cyc:
                cx ^= u
            cycle_lens.append(len(cyc))
            cycle_xors.append(cx)
            if cx != 0:
                all_cycles_xor0 = False
        for u in path:
            seen[u] = 2

    # coboundary V(F(x)) = V(x) ⊕ x exists globally iff every cycle XOR is 0
    # (trees can always be labelled once cycles are consistent)
    # measure typical orbit XOR vs endpoint formula
    rho_lens = []
    for _ in range(min(64, N)):
        x = RNG.randrange(N)
        seenp = {}
        u = x
        step = 0
        while u not in seenp:
            seenp[u] = step
            u = nxt[u]
            step += 1
            if step > N:
                break
        rho_lens.append(seenp[u])

    return {
        "params": str(p),
        "N": N,
        "image": image,
        "image_frac": round(image / N, 4),
        "n_cycles": len(cycle_lens),
        "cycle_len_min": min(cycle_lens) if cycle_lens else None,
        "cycle_len_max": max(cycle_lens) if cycle_lens else None,
        "cycle_len_median": statistics.median(cycle_lens) if cycle_lens else None,
        "all_cycles_xor0": all_cycles_xor0,
        "coboundary_V_exists": all_cycles_xor0,
        "note": (
            "coboundary V(F(x))=V(x)⊕x would give "
            "XOR_{k=0}^{n-1} F^k(x) = V(x)⊕V(F^n(x)). "
            "That still needs F^n; it only removes the running XOR. "
            "Existence requires every cycle XOR to vanish."
        ),
        "sample_rho_median": statistics.median(rho_lens) if rho_lens else None,
        "birthday_scale": round(N ** 0.5, 1),
    }


# ---------------------------------------------------------------------------
# 3. Related-message / cross-iteration fusion
# ---------------------------------------------------------------------------

def _compress_trace(env: Envelope, x: int, which: str):
    p = env.p
    words = unpack_state(x, p)
    from model import pad64_words

    block = pad64_words(words, p)
    iv = env.I if which == "inner" else env.O
    _, tr = compress(iv, block, p, trace=True)
    return tr


def related_message_scan(env: Envelope, samples: Sequence[int]) -> dict:
    """Look for exact relations between intermediates of F(x) and F(F(x))."""
    p = env.p
    # Collect candidate (kind, r, w) equality / xor-const / add-const
    # Only matching indices: cheap and the only relations that would give
    # a systematic skip of a named round.
    kinds = ("inner", "outer")
    # maps: name -> list of per-sample values (as ints)
    per: Dict[str, List[int]] = defaultdict(list)

    for x in samples:
        traces = {
            "F_inner": _compress_trace(env, x, "inner"),
        }
        traces["F_outer"] = _compress_trace(env, pack_state(traces["F_inner"].out, p), "outer")
        y = pack_state(traces["F_outer"].out, p)
        traces["G_inner"] = _compress_trace(env, y, "inner")
        traces["G_outer"] = _compress_trace(env, pack_state(traces["G_inner"].out, p), "outer")

        def dump(tag, tr):
            if tr is None:
                return
            for r, st in enumerate(tr.states):
                for wi, val in enumerate(st):
                    per[f"{tag}.s[{r},{wi}]"].append(val)
            for i, val in enumerate(tr.schedule):
                per[f"{tag}.W[{i}]"].append(val)
            for wi, val in enumerate(tr.out):
                per[f"{tag}.out[{wi}]"].append(val)

        for tag, tr in traces.items():
            dump(tag, tr)

    def relation(a: List[int], b: List[int]) -> Optional[str]:
        if a == b:
            return "eq"
        xors = {x ^ y for x, y in zip(a, b)}
        if len(xors) == 1:
            return f"xor_c:{xors.pop():x}"
        adds = {(x - y) & ((1 << p.w) - 1) for x, y in zip(a, b)}
        if len(adds) == 1:
            return f"add_c:{adds.pop():x}"
        return None

    matches = []
    # compare F_* vs G_* at the same names
    names_F = [k for k in per if k.startswith("F_")]
    for fk in names_F:
        gk = "G_" + fk[2:]
        if gk not in per:
            continue
        rel = relation(per[fk], per[gk])
        if rel:
            matches.append((fk, gk, rel))
    # also F_outer vs G_inner (the envelope seam of the next iterate)
    extra = []
    for fk in [k for k in per if k.startswith("F_outer")]:
        gk = "G_inner" + fk[len("F_outer") :]
        if gk in per:
            rel = relation(per[fk], per[gk])
            if rel:
                extra.append((fk, gk, rel))

    return {
        "params": str(p),
        "n_samples": len(samples),
        "same_slot_relations": matches[:40],
        "same_slot_count": len(matches),
        "seam_relations": extra[:20],
        "seam_count": len(extra),
        "note": (
            "A relation must hold for every sample. Padding schedule words "
            "W[8..15] are identical across iterations by construction."
        ),
        "nontrivial": [
            t
            for t in matches + extra
            if t[2] != "eq" and "W[8]" not in t[0] and "W[15]" not in t[0]
        ][:30],
    }


# ---------------------------------------------------------------------------
# 4. Linear / word invariants and homomorphic projections
# ---------------------------------------------------------------------------

def linear_invariants(env: Envelope, samples: Sequence[int]) -> dict:
    """Search c such that <c, F(x)> = <c, x> ⊕ b  (GF(2) bit pairing).

    On small domains we solve exactly; on large domains we solve the
    sampled linear system and reject any c that fails a hold-out set.
    """
    p = env.p
    bits = p.state_bits
    # Build equations over GF(2): (F(x) ⊕ x) · c = b, with b common.
    # First assume b=0: (F(x)⊕x) ⊥ c.  Then try b=1.
    rows = []
    for x in samples:
        rows.append((env.F(x) ^ x) & _bitmask(p))
    # Gaussian elimination on bit columns to find nullspace of rows
    null = _gf2_nullspace(rows, bits)
    hold = _sample_domain(p, 32)
    surviving = []
    for c in null:
        if c == 0:
            continue
        ok0 = all(((env.F(x) ^ x) & c).bit_count() % 2 == 0 for x in hold)
        if ok0:
            surviving.append(("parity_invariant", c))
    # word-xor projection: π(x) = xor of all words
    def word_xor(x: int) -> int:
        acc = 0
        for w in unpack_state(x, p):
            acc ^= w
        return acc

    wx_ok = all(word_xor(env.F(x)) == word_xor(x) for x in samples)
    wx_aff = False
    if samples:
        d0 = word_xor(env.F(samples[0])) ^ word_xor(samples[0])
        wx_aff = all((word_xor(env.F(x)) ^ word_xor(x)) == d0 for x in samples)

    # single-word homomorphism: flip every other word; word i of F must
    # stay put. Table-lookup on samples is useless at 64-bit width.
    word_closed = []
    for i in range(p.words):
        closed = True
        for x in samples[: min(16, len(samples))]:
            wds = unpack_state(x, p)
            fo = unpack_state(env.F(x), p)[i]
            flipped = list(wds)
            flipped[(i + 1) % p.words] ^= 1
            fo2 = unpack_state(env.F(pack_state(flipped, p)), p)[i]
            if fo2 != fo:
                closed = False
                break
        word_closed.append(closed)

    return {
        "params": str(p),
        "nullspace_dim_sample": len(null),
        "surviving_linear_invariants": len(surviving),
        "word_xor_invariant": wx_ok,
        "word_xor_affine": wx_aff,
        "per_word_closed": word_closed,
        "any_word_closed": any(word_closed),
    }


def _gf2_nullspace(rows: Sequence[int], bits: int) -> List[int]:
    """Return a basis of {c | row·c = 0 for all rows}."""
    A = list(rows)
    n = len(A)
    if n == 0:
        return [1 << i for i in range(bits)]
    # Row-reduce on columns 0..bits-1
    used = [-1] * bits
    r = 0
    for col in range(bits):
        piv = None
        for i in range(r, n):
            if (A[i] >> col) & 1:
                piv = i
                break
        if piv is None:
            continue
        A[r], A[piv] = A[piv], A[r]
        for i in range(n):
            if i != r and (A[i] >> col) & 1:
                A[i] ^= A[r]
        used[col] = r
        r += 1
        if r == n:
            break
    basis = []
    for free in range(bits):
        if used[free] != -1:
            continue
        c = 1 << free
        for col in range(bits):
            if used[col] != -1 and (A[used[col]] >> free) & 1:
                c |= 1 << col
        basis.append(c)
    return basis


# ---------------------------------------------------------------------------
# 5. Semigroup of the round family (tiny widths)
# ---------------------------------------------------------------------------

def round_semigroup(p: Params, max_elems: int = 4000) -> dict:
    """Monoid generated by the 2^w keyed round maps on the 8-register state.

    If this monoid is tiny, 80-round products could be table-driven.
    Transformations are stored as tuples of length 2^{min(state, 12)}.
    """
    # Use a reduced register count so the action is enumerable.
    bits = min(p.state_bits, 12)
    if bits < 4:
        return {"skipped": "too small"}
    N = 1 << bits
    # A "round" here is: apply one SHA-style update with a w-bit W on a
    # packed `bits`-bit state interpreted as words of size p.w (truncated).
    w = p.w
    nwords = min(p.words, max(1, bits // max(w, 1)))
    if nwords < 2:
        nwords = 2
        w = bits // 2

    def apply_round(state: int, W: int) -> int:
        words = [(state >> (i * w)) & ((1 << w) - 1) for i in range(nwords)]
        while len(words) < 8:
            words.append(SHA512_H[len(words)] & ((1 << w) - 1))
        a, b, c, d, e, f, g, h = words[:8]
        from model import big_sigma0, big_sigma1, ch, maj, k_word

        m = (1 << w) - 1
        s1 = big_sigma1(e, w)
        s0 = big_sigma0(a, w)
        if p.use_ch_maj:
            t1 = (h + s1 + ch(e, f, g, w) + k_word(0, w) + W) & m
            t2 = (s0 + maj(a, b, c, w)) & m
        else:
            t1 = (h + s1 + (e ^ f ^ g) + k_word(0, w) + W) & m
            t2 = (s0 + (a ^ b ^ c)) & m
        words = [(t1 + t2) & m, a, b, c, (d + t1) & m, e, f, g]
        out = 0
        for i in range(nwords):
            out |= (words[i] & ((1 << w) - 1)) << (i * w)
        return out & (N - 1)

    gens = []
    nW = min(1 << min(w, 6), 16)
    for W in range(nW):
        gens.append(tuple(apply_round(s, W) for s in range(N)))

    monoid = set(gens)
    frontier = list(gens)
    overflow = False
    while frontier:
        a = frontier.pop()
        for g in gens:
            prod = tuple(g[a[s]] for s in range(N))
            if prod not in monoid:
                monoid.add(prod)
                frontier.append(prod)
                if len(monoid) > max_elems:
                    overflow = True
                    frontier.clear()
                    break

    # collapse: is some generator idempotent / low order?
    orders = []
    for g in gens:
        cur = g
        order = 1
        idt = tuple(range(N))
        while cur != idt and order < 64:
            cur = tuple(g[cur[s]] for s in range(N))
            order += 1
        orders.append(order if cur == idt else None)

    return {
        "params": str(p),
        "action_bits": bits,
        "n_generators": len(gens),
        "monoid_size": len(monoid),
        "overflow": overflow,
        "generator_orders": orders,
        "collapsed": (not overflow) and len(monoid) < nW * p.rounds,
    }


# ---------------------------------------------------------------------------
# 6. Data-dependence / delayed state
# ---------------------------------------------------------------------------

def cone_of_influence(env: Envelope) -> dict:
    """Which inner output words affect the first k outer schedule / state words?

    If some inner word is unused for a long prefix of the outer compression,
    that word could be delayed. SHA-512's schedule uses W[0] and W[1] at
    W[16], so the answer is expected to be 'all 8 words immediately'.
    """
    p = env.p
    if p.words < 2:
        return {"params": str(p), "skipped": "single-word toy"}
    base = _sample_domain(p, 1)[0]
    base_words = unpack_state(base, p)
    from model import pad64_words

    inner, _ = compress(env.I, pad64_words(base_words, p), p)
    # flip each inner word, watch outer schedule / first states
    _, tr0 = compress(env.O, pad64_words(inner, p), p, trace=True)
    needed_for_W16 = set()
    needed_for_round0 = set()
    needed_for_out = set()
    for i in range(p.words):
        flipped = list(inner)
        flipped[i] ^= 1
        _, tr1 = compress(env.O, pad64_words(flipped, p), p, trace=True)
        if tr0.schedule != tr1.schedule:
            # first differing schedule word
            for j, (a, b) in enumerate(zip(tr0.schedule, tr1.schedule)):
                if a != b:
                    if j <= 16:
                        needed_for_W16.add(i)
                    break
        if tr0.states and tr0.states[0] != tr1.states[0]:
            needed_for_round0.add(i)
        if tr0.out != tr1.out:
            needed_for_out.add(i)
    return {
        "params": str(p),
        "inner_words_affecting_outer_W_le16": sorted(needed_for_W16),
        "inner_words_affecting_outer_round0": sorted(needed_for_round0),
        "inner_words_affecting_outer_out": sorted(needed_for_out),
        "can_delay_any_inner_word": len(needed_for_W16) < p.words
        or len(needed_for_round0) < p.words,
        "must_materialize_full_inner_digest": len(needed_for_W16) == p.words
        or len(needed_for_out) == p.words,
        "note": (
            "Outer round 0 uses only W[0], so later inner words do not "
            "affect the first outer round. They still all appear at the "
            "same instant (Davies-Meyer of the inner compression) and "
            "are all required before outer W[16] / the outer digest."
        ),
    }


# ---------------------------------------------------------------------------
# 7. HMAC I/O coupling (real midstates vs random IVs)
# ---------------------------------------------------------------------------

def io_coupling(trials: int = 24) -> dict:
    """I and O come from K⊕ipad / K⊕opad, which differ by 0x6a per byte.

    Test whether that induces an exact cheap relation between I and O, or
    extra identities in F that random IV pairs lack.
    """
    rel_xor_const = True
    rel_add_const = True
    rel_eq = True
    xor_c = None
    add_c = None
    for _ in range(trials):
        key = os.urandom(32)
        I, O = hmac_midstates(key)
        dx = tuple((a ^ b) for a, b in zip(I, O))
        da = tuple((a - b) & ((1 << 64) - 1) for a, b in zip(I, O))
        if xor_c is None:
            xor_c = dx
            add_c = da
        if dx != xor_c:
            rel_xor_const = False
        if da != add_c:
            rel_add_const = False
        if I != O:
            rel_eq = False

    # Compare identity-scan of real-I/O F vs random-I/O F on the full envelope
    p = Params(w=64, words=8, rounds=80, use_ch_maj=True, use_schedule=True, name="sha512")
    key = os.urandom(32)
    I, O = hmac_midstates(key)
    env_real = Envelope(p)
    env_real.I, env_real.O = I, O
    env_rand = Envelope(p, seed=0x1111)
    samples = [int.from_bytes(os.urandom(64), "big") for _ in range(16)]
    scan_real = identity_scan(env_real, samples, n_iter=4)
    scan_rand = identity_scan(env_rand, samples, n_iter=4)
    return {
        "I_eq_O": rel_eq,
        "I_xor_O_constant_across_keys": rel_xor_const,
        "I_minus_O_constant_across_keys": rel_add_const,
        "real_IO_identities": scan_real["true_identities"],
        "rand_IO_identities": scan_rand["true_identities"],
        "extra_identities_from_real_IO": sorted(
            set(scan_real["true_identities"]) - set(scan_rand["true_identities"])
        ),
    }


# ---------------------------------------------------------------------------
# 8. Full-width related-message sample (instrumented SHA-512)
# ---------------------------------------------------------------------------

def full_related_message(trials: int = 12) -> dict:
    key = os.urandom(32)
    I, O = hmac_midstates(key)
    # Compare F(x) vs F(F(x)) traces at matching (phase, round, word)
    eq_slots = None
    xorconst_slots = None
    for t in range(trials):
        x = list(struct.unpack(">8Q", os.urandom(64)))
        y = hmac64_F_words(I, O, x)
        z = hmac64_F_words(I, O, y)
        from model import compress as cpr

        p = Params(w=64, words=8, rounds=80, use_ch_maj=True, use_schedule=True, name="sha512")
        inner_x, tin = cpr(I, hmac64_pad_block(x), p, trace=True)
        outer_x, tout = cpr(O, hmac64_pad_block(inner_x), p, trace=True)
        inner_y, gin = cpr(I, hmac64_pad_block(outer_x), p, trace=True)
        outer_y, gout = cpr(O, hmac64_pad_block(inner_y), p, trace=True)
        assert outer_x == y and outer_y == z

        def slots(tr):
            out = {}
            for r, st in enumerate(tr.states):
                for wi, val in enumerate(st):
                    out[("s", r, wi)] = val
            for i, val in enumerate(tr.schedule):
                out[("W", i, 0)] = val
            return out

        pairs = [
            (slots(tin), slots(gin)),
            (slots(tout), slots(gout)),
            (slots(tout), slots(gin)),
        ]
        if eq_slots is None:
            eq_slots = [set() for _ in pairs]
            xorconst_slots = [dict() for _ in pairs]
            for pi, (A, B) in enumerate(pairs):
                for k in A:
                    if A[k] == B[k]:
                        eq_slots[pi].add(k)
                    xorconst_slots[pi][k] = A[k] ^ B[k]
        else:
            for pi, (A, B) in enumerate(pairs):
                eq_slots[pi] &= {k for k in A if A[k] == B[k]}
                dead = []
                for k, c in xorconst_slots[pi].items():
                    if (A[k] ^ B[k]) != c:
                        dead.append(k)
                for k in dead:
                    del xorconst_slots[pi][k]

    def summarize(eqset, xmap, label):
        # drop padding-schedule constants W[8..15] which are always equal
        eq_f = [k for k in sorted(eqset) if not (k[0] == "W" and 8 <= k[1] <= 15)]
        xor_f = [
            (k, c)
            for k, c in xmap.items()
            if c != 0 and not (k[0] == "W" and 8 <= k[1] <= 15)
        ]
        return {
            "label": label,
            "eq_nonpad": eq_f[:20],
            "eq_nonpad_count": len(eq_f),
            "xor_const_nonzero": xor_f[:10],
            "xor_const_nonzero_count": len(xor_f),
        }

    labels = ["Fin vs Gin (inners of F and F∘F)", "Fout vs Gout", "Fout vs Gin (seam)"]
    return {
        "trials": trials,
        "reports": [
            summarize(eq_slots[i], xorconst_slots[i], labels[i]) for i in range(3)
        ],
    }


# ---------------------------------------------------------------------------
# 9. Redundant / carry-save accounting (exact work, not a new kernel)
# ---------------------------------------------------------------------------

def carry_save_account(p: Params) -> dict:
    """Could keeping W_outer[0:7] = V + I in carry-save skip resolved adds?

    σ0/σ1 are bitwise and require a resolved word, so each expanded W[i]
    must be canonicalized before σ. The outer schedule therefore still
    pays a full add chain to materialize C = V+I (already paid by DM)
    and then the usual expansion. Carry-save does not remove a σ.
    """
    f = cost_F(p)
    # Optimistic fantasy: skip 8 DM adds by feeding (V,I) into the first
    # 8 outer T1 adders (K+I folded). That is 8 adds, once per F.
    saved = 8 if p.words >= 8 else p.words
    return {
        "params": str(p),
        "F_primitives": f.primitives,
        "optimistic_folded_I_adds": saved,
        "relative_save": round(saved / f.primitives, 6) if f.primitives else None,
        "survives_to_sha512": False,
        "reason": (
            "I is constant and can be folded into K[0..7] of the outer "
            "first 8 rounds (8 adds). σ on the outer schedule still needs "
            "the resolved inner digest. This is a <0.2% exact-add save."
        ),
    }


# ---------------------------------------------------------------------------
# 10. Symbolic composition / XOR-accumulation DAG
# ---------------------------------------------------------------------------

def symbolic_scale() -> List[dict]:
    rows = []
    # Keep this cheap: skip full 80-round symbolic (huge DAG, no extra rewrite
    # expected beyond what reduced models already show).
    for p in LADDER:
        if p.rounds > 16 or p.w > 16:
            continue
        env = Envelope(p)
        rows.append(dag_report(p, env.I, env.O, compose_n=2, xor_n=4))
        if p.rounds <= 8 and p.words <= 8:
            rows.append(dag_report(p, env.I, env.O, compose_n=4, xor_n=8))
    return rows


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 11. Quadratic invariants (state-space factorization)
# ---------------------------------------------------------------------------

def _gf2_rank_null_dim(rows: List[int], ncols: int) -> Tuple[int, int]:
    A = list(rows)
    n = len(A)
    used = [-1] * ncols
    r = 0
    for col in range(ncols):
        piv = None
        for i in range(r, n):
            if (A[i] >> col) & 1:
                piv = i
                break
        if piv is None:
            continue
        A[r], A[piv] = A[piv], A[r]
        for i in range(n):
            if i != r and (A[i] >> col) & 1:
                A[i] ^= A[r]
        used[col] = r
        r += 1
        if r == n:
            break
    n_free = sum(1 for u in used if u == -1)
    return r, n_free


def quadratic_invariants(env: Envelope) -> dict:
    """Solve q(F(x)) = q(x) for quadratic q over GF(2).

    Constants always work. Report extra dimension after removing the
    constant (and any linear invariants already counted).
    """
    p = env.p
    if not enumerable(p) or p.state_bits > 16:
        return {"params": str(p), "skipped": "not enumerable"}
    n = p.state_bits
    # monomials: 1, x_i, x_i x_j (i<j)
    pairs = [(i, j) for i in range(n) for j in range(i + 1, n)]
    ncols = 1 + n + len(pairs)

    def mons(x: int) -> int:
        bits = [(x >> i) & 1 for i in range(n)]
        vec = 1
        for i, b in enumerate(bits):
            if b:
                vec |= 1 << (1 + i)
        off = 1 + n
        for k, (i, j) in enumerate(pairs):
            if bits[i] and bits[j]:
                vec |= 1 << (off + k)
        return vec

    rows = []
    for x in range(1 << n):
        rows.append(mons(env.F(x)) ^ mons(x))
    rank, nfree = _gf2_rank_null_dim(rows, ncols)
    # At least the constant monomial is always invariant.
    extra = max(nfree - 1, 0)
    return {
        "params": str(p),
        "ncols": ncols,
        "rank": rank,
        "null_dim": nfree,
        "nonconstant_invariants": extra,
        "note": "extra>0 would split the state into a conserved coordinate",
    }


# ---------------------------------------------------------------------------
# 12. Berlekamp-Massey on n |-> DK bit (is there a short recurrence in n?)
# ---------------------------------------------------------------------------

def _berlekamp_massey(bits: List[int]) -> int:
    n = len(bits)
    c = [0] * n
    b = [0] * n
    c[0] = 1
    b[0] = 1
    L = 0
    m = 1
    for i in range(n):
        d = bits[i]
        for j in range(1, L + 1):
            d ^= c[j] & bits[i - j]
        if d == 0:
            m += 1
            continue
        t = c[:]
        for j in range(m, n):
            if j < n:
                c[j] ^= b[j - m]
        if 2 * L <= i:
            L = i + 1 - L
            b = t
            m = 1
        else:
            m += 1
    return L


def dk_linear_complexity(env: Envelope, n_max: int = 128, trials: int = 4) -> dict:
    p = env.p
    lcs = []
    for _ in range(trials):
        x = _sample_domain(p, 1)[0]
        seq = []
        u = x
        acc = 0
        for _i in range(n_max):
            u = env.F(u)
            acc ^= u
            seq.append(acc & 1)
        lcs.append(_berlekamp_massey(seq))
    return {
        "params": str(p),
        "n_max": n_max,
        "trials": trials,
        "lc_bit0": lcs,
        "lc_mean": round(sum(lcs) / len(lcs), 2),
        "random_seq_expect": n_max // 2,
        "note": (
            "If lc stays << n_max/2 as width grows, DK(n) has a short "
            "linear recurrence in the iteration index. Birthday-limited "
            "orbits on tiny models inflate this; SHA-512 should sit at ~n/2."
        ),
    }


# ---------------------------------------------------------------------------
# 13. Bit-blasted add: do carries cancel across F∘F?
# ---------------------------------------------------------------------------

def bitblast_compose(p: Params, I: Sequence[int], O: Sequence[int]) -> dict:
    if p.w > 8 or p.rounds > 8:
        return {"params": str(p), "skipped": "too wide for bit-blast"}
    # Encode each word as w bits. add becomes xor + carry chain.
    # We reuse the word DAG but expand add/rot at construction time.
    d = Dag(1)  # 1-bit nodes
    # Build w*words input bits
    xbits = [[d.var(f"x{j}_{b}") for b in range(p.w)] for j in range(p.words)]

    def bits_xor(a, b):
        return [d.xor(u, v) for u, v in zip(a, b)]

    def bits_and(a, b):
        return [d.and_(u, v) for u, v in zip(a, b)]

    def bits_not(a):
        return [d.not_(u) for u in a]

    def bits_rot(a, n):
        n %= p.w
        return a[n:] + a[:n] if n else a  # rot_r: bit0 is LSB; rot_r 1 sends bit0 to bit w-1? 
        # Our word rot_r(x,n): bit i goes to bit i-n. So new[i] = old[(i+n) % w]
        # new list where index=bit: new[i] = a[(i+n)%w]

    def rot_r_bits(a, n):
        n %= p.w
        return [a[(i + n) % p.w] for i in range(p.w)]

    def shr_bits(a, n):
        n = min(n, p.w)
        return [a[i + n] if i + n < p.w else d.c(0) for i in range(p.w)]

    def add_bits(a, b):
        out = []
        carry = d.c(0)
        for i in range(p.w):
            axb = d.xor(a[i], b[i])
            s = d.xor(axb, carry)
            carry = d.xor(d.and_(a[i], b[i]), d.and_(carry, axb))
            out.append(s)
        return out

    def const_bits(v):
        return [d.c((v >> i) & 1) for i in range(p.w)]

    def word_fn(op_word, *args):
        raise NotImplementedError

    def sig0(a):
        return bits_xor(bits_xor(rot_r_bits(a, 1), rot_r_bits(a, 8 % p.w)), shr_bits(a, 7))

    def sig1(a):
        return bits_xor(bits_xor(rot_r_bits(a, 19 % p.w), rot_r_bits(a, 61 % p.w)), shr_bits(a, 6))

    def bs0(a):
        return bits_xor(bits_xor(rot_r_bits(a, 28 % p.w), rot_r_bits(a, 34 % p.w)), rot_r_bits(a, 39 % p.w))

    def bs1(a):
        return bits_xor(bits_xor(rot_r_bits(a, 14 % p.w), rot_r_bits(a, 18 % p.w)), rot_r_bits(a, 41 % p.w))

    def chb(e, f, g):
        return bits_xor(bits_and(e, f), bits_and(bits_not(e), g))

    def majb(a, b, c):
        return bits_xor(bits_xor(bits_and(a, b), bits_and(a, c)), bits_and(b, c))

    def pad(xws):
        block = [const_bits(0) for _ in range(16)]
        nmsg = min(p.words, 8)
        for i in range(nmsg):
            block[i] = xws[i]
        pad_shift = max(p.w - 8, 0)
        block[nmsg] = const_bits((0x80 << pad_shift) & ((1 << p.w) - 1))
        block[15] = const_bits(HMAC64_BITLEN & ((1 << p.w) - 1))
        return block

    def compress_bits(iv, block):
        from model import SHA512_H, k_word

        reg = list(iv)
        while len(reg) < 8:
            reg.append(const_bits(SHA512_H[len(reg)] & ((1 << p.w) - 1)))
        sched = list(block)
        if p.use_schedule:
            while len(sched) < max(p.rounds, 16):
                sched.append(const_bits(0))
            for i in range(16, p.rounds):
                sched[i] = add_bits(
                    add_bits(sched[i - 16], sig0(sched[i - 15])),
                    add_bits(sched[i - 7], sig1(sched[i - 2])),
                )
        for i in range(p.rounds):
            a, b, c, dd, e, f, g, h = reg[:8]
            s1 = bs1(e)
            s0 = bs0(a)
            if p.use_ch_maj:
                t_ch = chb(e, f, g)
                t_maj = majb(a, b, c)
            else:
                t_ch = bits_xor(bits_xor(e, f), g)
                t_maj = bits_xor(bits_xor(a, b), c)
            temp1 = add_bits(add_bits(add_bits(add_bits(h, s1), t_ch), const_bits(k_word(i, p.w))), sched[i])
            temp2 = add_bits(s0, t_maj)
            new_e = add_bits(dd, temp1)
            new_a = add_bits(temp1, temp2)
            reg = [new_a, a, b, c, new_e, e, f, g] + reg[8:]
        return [add_bits(iv[j], reg[j]) for j in range(p.words)]

    def envelope(xws):
        i_iv = [const_bits(v) for v in I[: p.words]]
        o_iv = [const_bits(v) for v in O[: p.words]]
        mid = compress_bits(i_iv, pad(xws))
        return compress_bits(o_iv, pad(mid))

    y1 = envelope(xbits)
    s1 = d.live_count([bit for w in y1 for bit in w])
    y2 = envelope(y1)
    s2 = d.live_count([bit for w in y2 for bit in w])
    return {
        "params": str(p),
        "F_bitnodes": s1,
        "F2_bitnodes": s2,
        "F2_over_F": round(s2 / s1, 4) if s1 else None,
        "note": "add is xor+carry. Ratio ~2 means carries do not cancel across F∘F.",
    }


# ---------------------------------------------------------------------------
# 14. BDD iteration-closure
# ---------------------------------------------------------------------------

def bdd_closure(env: Envelope) -> dict:
    p = env.p
    if not enumerable(p):
        return {"params": str(p), "skipped": "not enumerable"}
    bits = p.state_bits
    rows = []
    for n in (1, 2, 4, 8, 16):
        t = compose_table(env.F, bits, n)
        rows.append({"kind": f"F^{n}", **bdd_sizes_from_table(t, bits)})
        if n in (2, 8, 16):
            xt = xor_prefix_table(env.F, bits, n)
            rows.append({"kind": f"DK_{n}", **bdd_sizes_from_table(xt, bits)})
    return {"params": str(p), "rows": rows}


def run_ladder_identity() -> List[dict]:
    rows = []
    for p in LADDER:
        env = Envelope(p)
        if enumerable(p):
            samples = list(_all_domain(p))
            # identity scan on a subset for speed; graph uses all
            scan_pts = samples if len(samples) <= 4096 else _sample_domain(p, SAMPLE_N)
        else:
            scan_pts = _sample_domain(p, SAMPLE_N)
            samples = scan_pts
        row = {
            "identity": identity_scan(env, scan_pts, n_iter=8),
            "invariants": linear_invariants(env, scan_pts),
            "cone": cone_of_influence(env),
        }
        if enumerable(p):
            row["graph"] = functional_graph(env)
        if p.rounds <= 16 and p.state_bits <= 64:
            row["related"] = related_message_scan(env, scan_pts[:24])
        rows.append(row)
    return rows


def run_all() -> dict:
    out = {
        "selfcheck": exp_selfcheck(),
        "ladder": run_ladder_identity(),
        "symbolic": symbolic_scale(),
        "io_coupling": io_coupling(),
        "full_related": full_related_message(),
        "carry_save": [carry_save_account(p) for p in LADDER if p.words >= 4],
        "semigroup": [
            round_semigroup(p)
            for p in LADDER
            if p.state_bits <= 16 and p.words >= 2
        ],
        "quadratic_invariants": [
            quadratic_invariants(Envelope(p)) for p in LADDER if enumerable(p)
        ],
        "dk_linear_complexity": [
            dk_linear_complexity(Envelope(p), n_max=64 if p.state_bits >= 32 else 128)
            for p in LADDER
            if p.rounds <= 16
        ],
        "bitblast": [
            bitblast_compose(p, Envelope(p).I, Envelope(p).O)
            for p in LADDER
            if p.w <= 8 and p.rounds <= 8
        ],
        "bdd_closure": [bdd_closure(Envelope(p)) for p in LADDER if enumerable(p)],
    }
    return out
