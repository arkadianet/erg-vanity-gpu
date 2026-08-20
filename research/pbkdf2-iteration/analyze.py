"""Exact analysis primitives for reduced F and G_n = XOR_i F^i.

None of these are production optimizations. They exist to distinguish
(A) fewer F evals, (B) fewer compressions, (C) fewer primitive ops
from representations that merely relocate the same work.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from models import Cost, Model, xor_iterates


def build_table(model: Model) -> np.ndarray:
    n = 1 << model.w
    t = np.empty(n, dtype=np.uint32)
    for x in range(n):
        t[x] = model.f(x)
    return t


def iterate_table(table: np.ndarray, x: np.ndarray, n: int) -> np.ndarray:
    y = x
    for _ in range(n):
        y = table[y]
    return y


def gn_table(table: np.ndarray, n: int) -> np.ndarray:
    """G_n(x) for every x, via n table walks. Exact."""
    N = table.shape[0]
    x = np.arange(N, dtype=np.uint32)
    acc = np.zeros(N, dtype=np.uint32)
    u = x
    for _ in range(n):
        u = table[u]
        acc ^= u
    return acc


def gn_table_doubling(table: np.ndarray, n: int) -> np.ndarray:
    """Same G_n via functional-graph doubling. O(2^w log n) table ops.

    This is cheaper than n×F only when the whole table of F is already
    materialized (state-space exhaustion). It is not a scalable circuit.
    """
    return _gn_doubling(table, n)


def _gn_doubling(table: np.ndarray, n: int) -> np.ndarray:
    N = table.shape[0]
    # succ[k][x] and xor[k][x] via binary lifting stored as current jump
    succ = table.copy()
    accxor = table.copy()  # XOR of the `step` iterates F(x)..F^step(x)
    step = 1
    # result starts at 0; apply binary digits of n from low to high
    x = np.arange(N, dtype=np.uint32)
    out = np.zeros(N, dtype=np.uint32)
    m = n
    cur = x
    while m:
        if m & 1:
            out ^= accxor[cur]
            cur = succ[cur]
        # double
        accxor = accxor ^ accxor[succ]
        succ = succ[succ]
        m >>= 1
    return out


def mobius(table: np.ndarray) -> np.ndarray:
    """ANF coefficients via Möbius transform over the boolean cube."""
    out = table.astype(np.uint32).copy()
    n = out.shape[0]
    step = 1
    while step < n:
        for i in range(0, n, step * 2):
            out[i + step : i + 2 * step] ^= out[i : i + step]
        step *= 2
    return out


def algebraic_degree(table: np.ndarray) -> int:
    anf = mobius(table)
    deg = 0
    nz = np.nonzero(anf)[0]
    for i in nz:
        wt = int(i).bit_count()
        if wt > deg:
            deg = wt
    return deg


def anf_term_count(table: np.ndarray, w: int) -> int:
    """Number of nonzero output-bit monomials in the ANF."""
    anf = mobius(table)
    terms = 0
    for b in range(w):
        terms += int(np.count_nonzero((anf >> b) & 1))
    return terms


def is_affine_table(table: np.ndarray, w: int) -> bool:
    n = 1 << w
    f0 = int(table[0])
    # F(x) ⊕ F(0) must be linear: check on a basis and a few sums
    basis = [1 << i for i in range(w)]
    images = [int(table[e]) ^ f0 for e in basis]
    for x in range(n):
        y = 0
        for i in range(w):
            if (x >> i) & 1:
                y ^= images[i]
        if y != (int(table[x]) ^ f0):
            return False
    return True


def is_tfunction_table(table: np.ndarray, w: int) -> bool:
    for bit in range(w):
        mask = (1 << (bit + 1)) - 1
        for x in range(1 << w):
            a = (int(table[x]) >> bit) & 1
            b = (int(table[x & mask]) >> bit) & 1
            if a != b:
                return False
    return True


def rand_state(rng: np.random.Generator, w: int) -> int:
    """Uniform w-bit integer (w may be 64)."""
    x = 0
    bits = 0
    while bits < w:
        take = min(32, w - bits)
        x |= int(rng.integers(0, 1 << take)) << bits
        bits += take
    return x


def tfunction_violations(model: Model, samples: int = 200, seed: int = 0) -> int:
    """How often bit i of F(x) differs from bit i of F(x with high bits cleared)."""
    rng = np.random.default_rng(seed)
    bad = 0
    w = model.w
    for _ in range(samples):
        x = rand_state(rng, w)
        bit = int(rng.integers(0, w))
        mask = (1 << (bit + 1)) - 1
        a = (model.f(x) >> bit) & 1
        b = (model.f(x & mask) >> bit) & 1
        bad += a != b
    return bad


def bitperm_tfunction_search(table: np.ndarray, w: int, trials: int, seed: int = 0) -> bool:
    """Is F conjugate to a T-function via a bit permutation?"""
    rng = np.random.default_rng(seed)
    n = 1 << w
    # always try identity first
    if is_tfunction_table(table, w):
        return True
    seen = set()
    for _ in range(trials):
        perm = rng.permutation(w)
        key = tuple(perm.tolist())
        if key in seen:
            continue
        seen.add(key)
        # y = π(F(π^{-1}(y)))
        inv = np.empty(w, dtype=np.int64)
        inv[perm] = np.arange(w)
        conj = np.empty(n, dtype=np.uint32)
        for y in range(n):
            x = _perm_bits(y, inv, w)
            fx = int(table[x])
            conj[y] = _perm_bits(fx, perm, w)
        if is_tfunction_table(conj, w):
            return True
    return False


def _perm_bits(x: int, perm, w: int) -> int:
    y = 0
    for i in range(w):
        if (x >> i) & 1:
            y |= 1 << int(perm[i])
    return y


def gf2_rank(rows: list[np.ndarray]) -> int:
    """Rank over GF(2) of bit-vectors packed as uint64 arrays of equal length."""
    if not rows:
        return 0
    A = np.vstack(rows).copy()
    n, m = A.shape
    rank = 0
    col = 0
    # process 64 columns at a time
    total_bits = m * 64
    for bitpos in range(total_bits):
        word, b = divmod(bitpos, 64)
        if word >= m:
            break
        mask = np.uint64(1) << np.uint64(b)
        piv = None
        for r in range(rank, n):
            if A[r, word] & mask:
                piv = r
                break
        if piv is None:
            continue
        if piv != rank:
            A[[rank, piv]] = A[[piv, rank]]
        # eliminate
        sel = (A[:, word] & mask) != 0
        sel[rank] = False
        A[sel] ^= A[rank]
        rank += 1
        if rank == n:
            break
    return rank


def _pack_bits(bits: np.ndarray) -> np.ndarray:
    bits = bits.astype(np.uint8)
    pad = (-bits.size) % 64
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
    return np.packbits(bits, bitorder="little").view(np.uint64)


def koopman_krylov_ranks(table: np.ndarray, w: int, max_k: int) -> list[int]:
    """Rank of {coord bits of id, F, F^2, ..., F^k} as Boolean functions."""
    N = table.shape[0]
    cur = np.arange(N, dtype=np.uint32)
    rows: list[np.ndarray] = []
    ranks = []
    for k in range(max_k + 1):
        for b in range(w):
            rows.append(_pack_bits((cur >> b) & 1))
        ranks.append(gf2_rank(rows))
        cur = table[cur]
    return ranks


def walsh_nonzero(bit_fn: np.ndarray) -> int:
    """Nonzero Walsh coefficients of a 0/1 Boolean function."""
    v = 1 - 2 * bit_fn.astype(np.int32)
    n = v.shape[0]
    h = 1
    while h < n:
        for i in range(0, n, h * 2):
            a = v[i : i + h].copy()
            b = v[i + h : i + 2 * h]
            v[i : i + h] = a + b
            v[i + h : i + 2 * h] = a - b
        h *= 2
    return int(np.count_nonzero(v))


def walsh_sparsity(table: np.ndarray, w: int) -> dict:
    N = table.shape[0]
    spars = []
    for b in range(w):
        spars.append(walsh_nonzero((table >> b) & 1))
    return {
        "min": min(spars),
        "max": max(spars),
        "mean": sum(spars) / len(spars),
        "full": N,
    }


def berlekamp_massey(seq: list[int]) -> list[int]:
    """Minimal LFSR over GF(2). Returns connection polynomial (c_0=1)."""
    n = len(seq)
    c = [1] + [0] * n
    b = [1] + [0] * n
    L = 0
    m = 1
    for i in range(n):
        d = seq[i]
        for j in range(1, L + 1):
            d ^= c[j] & seq[i - j]
        if d == 0:
            m += 1
            continue
        t = c[:]
        for j in range(m, n):
            c[j] ^= b[j - m]
        if 2 * L <= i:
            L = i + 1 - L
            b = t
            m = 1
        else:
            m += 1
    return c[: L + 1]


def iterate_sequence(model: Model, x: int, n: int) -> list[int]:
    seq = []
    u = x
    for _ in range(n):
        u = model.f(u)
        seq.append(u)
    return seq


def linear_complexities(seq: list[int], w: int) -> list[int]:
    out = []
    for b in range(w):
        bits = [(v >> b) & 1 for v in seq]
        out.append(len(berlekamp_massey(bits)) - 1)
    return out


def jacobian_gf2(model: Model, x: int) -> list[int]:
    """Columns J_i = F(x⊕e_i) ⊕ F(x)."""
    fx = model.f(x)
    cols = []
    for i in range(model.w):
        cols.append(model.f(x ^ (1 << i)) ^ fx)
    return cols


def jacobian_constant(model: Model, samples: int = 40, seed: int = 0) -> bool:
    rng = np.random.default_rng(seed)
    base = None
    for _ in range(samples):
        x = rand_state(rng, model.w)
        J = tuple(jacobian_gf2(model, x))
        if base is None:
            base = J
        elif J != base:
            return False
    return True


def invariant_linear_forms(table: np.ndarray, w: int) -> int:
    """Count nonzero L where L·F(x) is a function of L·x only."""
    N = 1 << w
    found = 0
    for L in range(1, N):
        # map parity(L·x) -> set of L·F(x)
        seen = {}
        ok = True
        for x in range(N):
            pin = _parity(L & x)
            pout = _parity(L & int(table[x]))
            if pin not in seen:
                seen[pin] = pout
            elif seen[pin] != pout:
                ok = False
                break
        if ok:
            found += 1
    return found


def _parity(x: int) -> int:
    return x.bit_count() & 1


def degree_profile(table: np.ndarray, ns: list[int], w: int) -> list[dict]:
    rows = []
    N = table.shape[0]
    idt = np.arange(N, dtype=np.uint32)
    fk = idt.copy()
    for k in range(1, max(ns) + 1):
        fk = table[fk]
        if k in ns:
            gn = gn_table(table, k)
            deg_f = algebraic_degree(fk)
            deg_g = algebraic_degree(gn)
            rows.append(
                {
                    "n": k,
                    "deg_Fn": deg_f,
                    "deg_Gn": deg_g,
                    "anf_Fn": anf_term_count(fk, w),
                    "anf_Gn": anf_term_count(gn, w),
                    "deg_cancelled": deg_g < deg_f,
                }
            )
    return rows


def hx_vs_f(table: np.ndarray, w: int) -> dict:
    """H(x) = x ⊕ F(x) versus F."""
    N = table.shape[0]
    x = np.arange(N, dtype=np.uint32)
    h = x ^ table
    return {
        "deg_F": algebraic_degree(table),
        "deg_H": algebraic_degree(h),
        "anf_F": anf_term_count(table, w),
        "anf_H": anf_term_count(h, w),
        "affine_F": is_affine_table(table, w),
        "affine_H": is_affine_table(h, w),
    }


def cycle_stats(table: np.ndarray) -> dict:
    N = table.shape[0]
    seen = np.zeros(N, dtype=np.uint8)
    cycles = []
    for s in range(N):
        if seen[s]:
            continue
        path = {}
        x = s
        i = 0
        while x not in path and not seen[x]:
            path[x] = i
            x = int(table[x])
            i += 1
        if x in path:
            cycles.append(i - path[x])
        for y in path:
            seen[y] = 1
    return {
        "n_cycles": len(cycles),
        "cycle_lens": sorted(cycles, reverse=True)[:8],
        "max_cycle": max(cycles) if cycles else 0,
        "is_permutation": len(set(int(v) for v in table)) == N,
    }


# ---------------------------------------------------------------------------
# Closed-form G_n for affine maps over GF(2)
# F(x) = A x ⊕ b.  This is the control that MUST beat n×F.
# ---------------------------------------------------------------------------

def extract_affine(table: np.ndarray, w: int) -> tuple[list[int], int] | None:
    if not is_affine_table(table, w):
        return None
    b = int(table[0])
    A = [int(table[1 << i]) ^ b for i in range(w)]
    return A, b


def apply_A(A: list[int], x: int) -> int:
    y = 0
    for i, col in enumerate(A):
        if (x >> i) & 1:
            y ^= col
    return y


def mat_mul(A: list[int], B: list[int], w: int) -> list[int]:
    return [apply_A(A, B[i] if i < len(B) else 0) for i in range(w)]


def mat_pow(A: list[int], e: int, w: int) -> list[int]:
    # identity
    R = [1 << i for i in range(w)]
    P = A[:]
    while e:
        if e & 1:
            R = mat_mul(P, R, w)
        P = mat_mul(P, P, w)
        e >>= 1
    return R


def affine_gn_closed(A: list[int], b: int, x: int, n: int, w: int) -> tuple[int, int]:
    """G_n for F(z)=A z ⊕ b via affine-semigroup doubling. O(w^3 log n) xors."""
    I = [1 << i for i in range(w)]
    ops = 0
    out_A = I
    out_b = 0
    out_C = [0] * w
    out_d = 0
    curA, curb = A[:], b
    curC, curd = A[:], b
    m = n
    while m:
        if m & 1:
            # G_new(x) = G_out(x) ⊕ G_cur(F_out(x))
            # F_out(x) = outA x ⊕ outb
            # G_cur(z) = curC z ⊕ curd
            # G_cur(F_out(x)) = curC (outA x ⊕ outb) ⊕ curd
            composed_C = [apply_A(curC, out_A[i]) for i in range(w)]
            composed_d = apply_A(curC, out_b) ^ curd
            out_C = [out_C[i] ^ composed_C[i] for i in range(w)]
            out_d ^= composed_d
            # F_new = F_cur ∘ F_out
            newA = [apply_A(curA, out_A[i]) for i in range(w)]
            newb = apply_A(curA, out_b) ^ curb
            out_A, out_b = newA, newb
        # double cur
        # G_2m(x) = G_m(x) ⊕ G_m(F_m(x))
        composed_C = [apply_A(curC, curA[i]) for i in range(w)]
        composed_d = apply_A(curC, curb) ^ curd
        curC = [curC[i] ^ composed_C[i] for i in range(w)]
        curd ^= composed_d
        newA = [apply_A(curA, curA[i]) for i in range(w)]
        newb = apply_A(curA, curb) ^ curb
        curA, curb = newA, newb
        m >>= 1
        ops += 4 * w * w
    gn = apply_A(out_C, x) ^ out_d
    return gn, ops


def naive_cost(model: Model, n: int, x: int = 1) -> int:
    c = Cost()
    xor_iterates(model, x, n, c)
    return c.total


@dataclass
class EquivResult:
    ok: bool
    n: int
    x: int
    naive: int
    other: int


def check_equiv(model: Model, n: int, other_fn, samples: int = 20, seed: int = 0) -> list[EquivResult]:
    rng = np.random.default_rng(seed)
    out = []
    for _ in range(samples):
        x = rand_state(rng, model.w)
        a = xor_iterates(model, x, n)
        b = other_fn(x, n)
        out.append(EquivResult(ok=(a == b), n=n, x=x, naive=a, other=b))
    return out
