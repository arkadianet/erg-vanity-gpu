#!/usr/bin/env python3
"""Representations that could make T = XOR_i F^i cheaper than n evals of F.

Not repeated: Koopman/Walsh/G2-SAT/ANF-doubling/bitslice/CSA/ROTR/CSE.

1. Univariate interpolation over GF(256) (sparsity, linearized support)
2. Low-degree Abel/Schröder conjugacy; Dickson/Frobenius
3. HMAC sandwich F = H_O ∘ H_I, Q = H_I ∘ H_O
4. Unfolding / MPO ranks of F^n and G_n
5. GF(256) Berlekamp–Massey on packed orbits
6. Commutant against a library of simple maps
7. Linear semiconjugacy tower (exact test for linear conjugacy to a T-function)
8. Affine-over-GF(256) conjugacy onto a cheap normal form
9. Finite differences of the orbit and of G(n) in the iteration index
10. Cycle type / image size (document the 8-bit table trap)
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np

from analyze import algebraic_degree, build_table, gn_table
from gf256 import eval_poly, interpolate, inv, mul, sparsity
from models import arx_chmaj_map, linear_map, mini_hmac, mini_hmac_parts, quadratic_map

HERE = Path(__file__).resolve().parent
OUT = HERE / "results"
OUT.mkdir(exist_ok=True)


def log(msg: str) -> None:
    print(msg, flush=True)


def table_list(model) -> list[int]:
    return [int(v) for v in build_table(model)]


def interpolant_stats(ys: list[int]) -> dict:
    c = interpolate(ys)
    ok = all(eval_poly(c, x) == ys[x] for x in (0, 1, 7, 99, 255))
    s = sparsity(c)
    s["verified"] = ok
    return s


def gf_solve_homogeneous(rows: list[list[int]]) -> list[list[int]]:
    if not rows:
        return []
    m, n = len(rows), len(rows[0])
    A = [r[:] for r in rows]
    rnk = 0
    piv = [-1] * n
    for col in range(n):
        p = next((i for i in range(rnk, m) if A[i][col]), None)
        if p is None:
            continue
        A[rnk], A[p] = A[p], A[rnk]
        ip = inv(A[rnk][col])
        for j in range(n):
            A[rnk][j] = mul(A[rnk][j], ip)
        for i in range(m):
            if i == rnk or A[i][col] == 0:
                continue
            f = A[i][col]
            for j in range(n):
                A[i][j] ^= mul(f, A[rnk][j])
        piv[col] = rnk
        rnk += 1
        if rnk == m:
            break
    free = [j for j in range(n) if piv[j] < 0]
    basis = []
    for f in free:
        v = [0] * n
        v[f] = 1
        for j, pr in enumerate(piv):
            if pr >= 0:
                v[j] = A[pr][f]
        basis.append(v)
    return basis


def _gf_particular(rows, rhs):
    m, n = len(rows), len(rows[0])
    A = [rows[i][:] + [rhs[i]] for i in range(m)]
    rnk = 0
    piv_col = []
    for col in range(n):
        p = next((i for i in range(rnk, m) if A[i][col]), None)
        if p is None:
            continue
        A[rnk], A[p] = A[p], A[rnk]
        ip = inv(A[rnk][col])
        for j in range(n + 1):
            A[rnk][j] = mul(A[rnk][j], ip)
        for i in range(m):
            if i == rnk or A[i][col] == 0:
                continue
            f = A[i][col]
            for j in range(n + 1):
                A[i][j] ^= mul(f, A[rnk][j])
        piv_col.append(col)
        rnk += 1
    for i in range(m):
        if all(A[i][j] == 0 for j in range(n)) and A[i][n]:
            return None
    x = [0] * n
    for i, col in enumerate(piv_col):
        x[col] = A[i][n]
    return x


def conjugacy_to_translation(ys: list[int], deg: int) -> dict:
    """Exists deg≤d ψ, not constant, with ψ(F(x)) = ψ(x) ⊕ 1 for all x?"""
    rows = []
    rhs = []
    for x in range(256):
        fx = ys[x]
        row = []
        pk_f, pk_x = 1, 1
        for _k in range(deg + 1):
            row.append(pk_f ^ pk_x)
            pk_f = mul(pk_f, fx)
            pk_x = mul(pk_x, x)
        rows.append(row)
        rhs.append(1)
    ns = gf_solve_homogeneous(rows)
    particular = _gf_particular(rows, rhs)
    nonconst = bool(
        (particular and any(particular[1:])) or any(any(v[1:]) for v in ns)
    )
    return {
        "deg": deg,
        "particular": particular is not None,
        "nullspace_dim": len(ns),
        "exists_nonconst": nonconst,
        "coeff": particular,
    }


def conjugacy_to_multiply(ys: list[int], deg: int, alphas: list[int]) -> dict:
    """ψ(F(x)) = α ψ(x), ψ not 0. Try listed α."""
    hits = []
    for alpha in alphas:
        rows = []
        for x in range(256):
            fx = ys[x]
            row = []
            pk_f, pk_x = 1, 1
            for _k in range(deg + 1):
                row.append(pk_f ^ mul(alpha, pk_x))
                pk_f = mul(pk_f, fx)
                pk_x = mul(pk_x, x)
            rows.append(row)
        ns = gf_solve_homogeneous(rows)
        useful = [v for v in ns if any(v)]
        if useful:
            hits.append({"alpha": alpha, "dim": len(useful), "sample": useful[0]})
    return {"deg": deg, "n_alpha_tried": len(alphas), "hits": hits}


def conjugacy_affine_to_frobenius(ys: list[int]) -> bool:
    """Exists affine ψ(z)=az⊕b, a≠0, with ψ(F(x)) = ψ(x)^2."""
    for a in range(1, 256):
        for b in range(256):
            ok = True
            for x in range(256):
                lhs = mul(a, ys[x]) ^ b
                t = mul(a, x) ^ b
                if lhs != mul(t, t):
                    ok = False
                    break
            if ok:
                return True
    return False


def dickson2(x: int, _a: int) -> int:
    return mul(x, x)


def is_dickson_or_affine_conj(ys: list[int]) -> dict:
    return {
        "affine_conj_to_square": conjugacy_affine_to_frobenius(ys),
        "equals_square": all(ys[x] == dickson2(x, 0) for x in range(256)),
    }


def unfolding_ranks(ys: list[int]) -> dict:
    t = np.array(ys, dtype=np.int64).reshape(4, 4, 4, 4)
    vec_ranks = []
    for a in (4, 16, 64):
        M = t.reshape(a, 256 // a)
        vec_ranks.append(int(np.linalg.matrix_rank(M)))
    T = np.zeros((4, 4, 4, 4, 4, 4, 4, 4), dtype=np.float64)
    for x, y in enumerate(ys):
        xs = [(x >> (2 * i)) & 3 for i in range(4)]
        ys_ = [(y >> (2 * i)) & 3 for i in range(4)]
        T[tuple(xs + ys_)] = 1.0
    inter = np.transpose(T, (0, 4, 1, 5, 2, 6, 3, 7))
    mpo = []
    for k in (1, 2, 3):
        M = inter.reshape(16**k, 16 ** (4 - k))
        mpo.append(int(np.linalg.matrix_rank(M)))
    return {"value_tensor_ranks_R": vec_ranks, "mpo_unfolding_ranks_R": mpo}


def gf2_unfolding_ranks(ys: list[int]) -> list[int]:
    T = np.zeros((16, 16, 16, 16), dtype=np.uint8)
    for x, y in enumerate(ys):
        sites = []
        for i in range(4):
            xi = (x >> (2 * i)) & 3
            yi = (y >> (2 * i)) & 3
            sites.append(xi | (yi << 2))
        T[tuple(sites)] = 1
    ranks = []
    for k in (1, 2, 3):
        M = T.reshape(16**k, 16 ** (4 - k))
        ranks.append(_gf2_rank(M))
    return ranks


def _gf2_rank(M: np.ndarray) -> int:
    A = (M & 1).astype(np.uint8).copy()
    n, m = A.shape
    r = 0
    for c in range(m):
        p = None
        for i in range(r, n):
            if A[i, c]:
                p = i
                break
        if p is None:
            continue
        if p != r:
            A[[r, p]] = A[[p, r]]
        sel = A[:, c] == 1
        sel[r] = False
        A[sel] ^= A[r]
        r += 1
        if r == n:
            break
    return r


def bm_gf256(seq: list[int]) -> int:
    n = len(seq)
    C = [1] + [0] * n
    B = [1] + [0] * n
    L = 0
    m = 1
    b = 1
    for N in range(n):
        d = seq[N]
        for i in range(1, L + 1):
            d ^= mul(C[i], seq[N - i])
        if d == 0:
            m += 1
            continue
        T = C[:]
        coef = mul(d, inv(b))
        for i in range(m, n):
            C[i] ^= mul(coef, B[i - m])
        if 2 * L <= N:
            L = N + 1 - L
            B = T
            b = d
            m = 1
        else:
            m += 1
    return L


def commute_library(ys: list[int]) -> dict:
    hits = []

    def apply_c(kind, p, x):
        if kind == "xor":
            return x ^ p
        if kind == "add256":
            return (x + p) & 255
        if kind == "mul_odd":
            return (x * p) & 255
        if kind == "rot":
            return ((x >> p) | (x << (8 - p))) & 255
        if kind == "word_add":
            out = 0
            for i in range(4):
                w = ((x >> (2 * i)) & 3) + (p & 3)
                out |= (w & 3) << (2 * i)
            return out
        return x

    for kind, params in (
        ("xor", range(256)),
        ("add256", range(256)),
        ("mul_odd", [1, 3, 5, 7, 9, 15, 17, 51, 85]),
        ("rot", range(8)),
        ("word_add", range(4)),
    ):
        for p in params:
            if kind == "xor" and p == 0:
                hits.append(f"{kind}:0=id")
                continue
            ok = True
            for x in range(256):
                if ys[apply_c(kind, p, x)] != apply_c(kind, p, ys[x]):
                    ok = False
                    break
            if ok:
                hits.append(f"{kind}:{p}")
    return {"commuting": hits}


def _popparity_table(n: int) -> np.ndarray:
    par = np.zeros(n, dtype=np.uint8)
    for i in range(1, n):
        par[i] = par[i >> 1] ^ (i & 1)
    return par


def linear_semiconjugacy(ys: list[int], w: int | None = None) -> dict:
    """1-bit linear quotients, and the tallest T-function flag they generate.

    F is linearly conjugate to a T-function iff there is a full flag
    a0..a{w-1} of linear forms with (a0..ak)∘F a function of (a0..ak)∘id
    for every k. In particular there must exist at least one 1-bit quotient.
    """
    N = len(ys)
    if w is None:
        w = int(N).bit_length() - 1
    t = np.array(ys, dtype=np.uint32)
    x = np.arange(N, dtype=np.uint32)
    par = _popparity_table(N)

    def is_quotient(forms: list[int]) -> bool:
        k = len(forms)
        seen = [-1] * (1 << k)
        # small k: python loop is fine at N=256
        for v in range(N):
            xin = 0
            xout = 0
            for i, a in enumerate(forms):
                xin |= int(par[v & a]) << i
                xout |= int(par[int(t[v]) & a]) << i
            if seen[xin] < 0:
                seen[xin] = xout
            elif seen[xin] != xout:
                return False
        return True

    onebit = [a for a in range(1, N) if is_quotient([a])]
    max_height = 1 if onebit else 0
    best_flag: list[int] = [onebit[0]] if onebit else []
    # Greedy extend each 1-bit quotient. For w=8 this is cheap.
    for a0 in onebit:
        flag = [a0]
        span = {0, a0}
        # close span under xor as we add
        grew = True
        while grew and len(flag) < w:
            grew = False
            for a in range(1, N):
                if a in span:
                    continue
                if is_quotient(flag + [a]):
                    flag.append(a)
                    new = {s ^ a for s in span}
                    span |= new
                    grew = True
                    break
        if len(flag) > max_height:
            max_height = len(flag)
            best_flag = flag
        if max_height == w:
            break

    return {
        "n_1bit_quotients": len(onebit),
        "max_flag_height": max_height,
        "full_T_conjugacy": max_height == w,
        "best_flag": best_flag,
        "onebit_sample": onebit[:12],
    }


def affine_conj_to_cheap(ys: list[int]) -> dict:
    """Search ψ(z)=az⊕b over GF(256) such that ψ F ψ^{-1} is a cheap map."""
    hits = []
    # Precompute F
    for a in range(1, 256):
        ia = inv(a)
        for b in range(256):
            # N(z) = a*F(ia*(z⊕b)) ⊕ b
            # classify without storing if possible
            kind = _classify_cheap_conj(ys, a, b, ia)
            if kind:
                hits.append({"a": a, "b": b, "form": kind})
                # one hit of each form is enough
                if len(hits) >= 8:
                    return {"hits": hits, "stopped_early": True}
    return {"hits": hits, "stopped_early": False}


def _classify_cheap_conj(ys, a, b, ia) -> str | None:
    # evaluate N at 0,1,2,3 first for cheap filters, then all 256
    def N(z: int) -> int:
        x = mul(ia, z ^ b)
        return mul(a, ys[x]) ^ b

    n0 = N(0)
    # translation z ⊕ c
    c = n0  # N(0)=c
    if all(N(z) == (z ^ c) for z in range(256)):
        return f"xor:{c}"
    # add z + c  (c = n0)
    if all(N(z) == ((z + n0) & 255) for z in range(256)):
        return f"add:{n0}"
    # square
    if all(N(z) == mul(z, z) for z in range(256)):
        return "square"
    # square ⊕ c
    if all(N(z) == (mul(z, z) ^ n0) for z in range(256)):
        return f"square_xor:{n0}"
    # multiply by constant: N(z)=μ z, N(0) must be 0
    if n0 == 0:
        mu = N(1)
        if mu and all(N(z) == mul(mu, z) for z in range(256)):
            return f"mul:{mu}"
        # power z^{2^k}
        for e in (2, 4, 8, 16, 32, 64, 128):
            ok = True
            p = 1
            # check a few then all
            for z in range(256):
                if N(z) != pow_small(z, e):
                    ok = False
                    break
            if ok:
                return f"power:{e}"
    # rotation
    for r in range(1, 8):
        if all(N(z) == (((z >> r) | (z << (8 - r))) & 255) for z in range(256)):
            return f"rot:{r}"
    return None


def pow_small(z: int, e: int) -> int:
    r = 1
    ee = e
    zz = z
    while ee:
        if ee & 1:
            r = mul(r, zz)
        zz = mul(zz, zz)
        ee >>= 1
    return r


def finite_diff_order(seq: list[int], mode: str) -> int | None:
    """Smallest d with vanishing d-th difference, or None."""
    s = list(seq)
    for d in range(1, len(s)):
        if mode == "xor":
            s = [s[i + 1] ^ s[i] for i in range(len(s) - 1)]
        elif mode == "add256":
            s = [(s[i + 1] - s[i]) & 255 for i in range(len(s) - 1)]
        elif mode == "gf256":
            # same as xor: field add is XOR
            s = [s[i + 1] ^ s[i] for i in range(len(s) - 1)]
        else:
            raise ValueError(mode)
        if all(v == 0 for v in s):
            return d
    return None


def orbit_and_G_diffs(ys: list[int], x0: int, length: int = 80) -> dict:
    u = x0
    orb = []
    g = 0
    gs = []
    for _ in range(length):
        u = ys[u]
        orb.append(u)
        g ^= u
        gs.append(g)
    return {
        "orbit_xor_diff": finite_diff_order(orb, "xor"),
        "orbit_add_diff": finite_diff_order(orb, "add256"),
        "G_xor_diff": finite_diff_order(gs, "xor"),
        "G_add_diff": finite_diff_order(gs, "add256"),
    }


def cycle_type(ys: list[int]) -> dict:
    N = len(ys)
    seen = [False] * N
    cycles = []
    tails = 0
    # functional graph: find cycles via tortoise, count cycle lengths
    for s in range(N):
        if seen[s]:
            continue
        path = []
        idx = {}
        x = s
        while x not in idx and not seen[x]:
            idx[x] = len(path)
            path.append(x)
            x = ys[x]
        if x in idx:
            cycles.append(len(path) - idx[x])
            tails += idx[x]
        for v in path:
            seen[v] = True
    cycles.sort(reverse=True)
    im = len(set(ys))
    return {
        "n_cycles": len(cycles),
        "cycle_lengths": cycles[:16],
        "tail_nodes_approx": tails,
        "image_size": im,
        "bijective": im == N,
    }


def sandwich(nwords, bits, rounds, seed) -> dict:
    parts = mini_hmac_parts(nwords, bits, rounds, seed)
    hi = table_list(parts["H_I"])
    ho = table_list(parts["H_O"])
    f = table_list(parts["F"])
    q = [hi[ho[x]] for x in range(len(hi))]

    def qn(x, n):
        for _ in range(n):
            x = q[x]
        return x

    ident_ok = True
    for n in (1, 2, 3, 5, 8):
        u = 17
        for _ in range(n):
            u = f[u]
        if u != ho[qn(hi[17], n - 1)]:
            ident_ok = False
    return {
        "identity_Fn_HO_Q_HI": ident_ok,
        "interp_HI": interpolant_stats(hi),
        "interp_HO": interpolant_stats(ho),
        "interp_Q": interpolant_stats(q),
        "interp_F": interpolant_stats(f),
        "deg_Q": algebraic_degree(np.array(q, dtype=np.uint32)),
        "deg_F": algebraic_degree(np.array(f, dtype=np.uint32)),
        "Q_eq_F": q == f,
        "order_Q": _func_order(q),
        "order_F": _func_order(f),
        "im_HI": len(set(hi)),
        "im_HO": len(set(ho)),
        "im_Q": len(set(q)),
        "im_F": len(set(f)),
        "Q_semiconj": linear_semiconjugacy(q),
        "F_semiconj": linear_semiconjugacy(f),
        "HI_semiconj": linear_semiconjugacy(hi),
        "HO_semiconj": linear_semiconjugacy(ho),
    }


def _func_order(ys: list[int]) -> int | None:
    cur = list(range(len(ys)))
    for k in range(1, 65):
        cur = [ys[v] for v in cur]
        if cur == list(range(len(ys))):
            return k
    return None


def verify_interpolate() -> None:
    # identity
    idys = list(range(256))
    c = interpolate(idys)
    assert eval_poly(c, 0) == 0 and eval_poly(c, 7) == 7 and eval_poly(c, 200) == 200
    assert sparsity(c)["nonzero"] == 1
    # linearized control
    lin = table_list(linear_map(8, seed=11))
    c = interpolate(lin)
    assert all(eval_poly(c, x) == lin[x] for x in range(0, 256, 17))


def main() -> int:
    t0 = time.time()
    log("=== novel representations ===")
    verify_interpolate()
    log("interpolate self-check ok")

    lin = table_list(linear_map(8, seed=11))
    log("control linear interpolant")
    lin_s = interpolant_stats(lin)
    log(f"  {lin_s}")

    models = [
        ("linear", lin),
        ("quadratic", table_list(quadratic_map(8, seed=12))),
        ("hmac_r2", table_list(mini_hmac(4, 2, 2, seed=21))),
        ("hmac_r3", table_list(mini_hmac(4, 2, 3, seed=21))),
        ("hmac_r4", table_list(mini_hmac(4, 2, 4, seed=21))),
        ("hmac_r8", table_list(mini_hmac(4, 2, 8, seed=21))),
        ("arxch_r4", table_list(arx_chmaj_map(4, 2, 4, seed=5))),
    ]

    interp = {}
    conj = {}
    ranks = {}
    commute = {}
    bm = {}
    semi = {}
    cheap = {}
    diffs = {}
    cycles = {}

    for name, ys in models:
        log(f"-- {name}")
        st = interpolant_stats(ys)
        interp[name] = st
        log(f"  interpolant {st}")

        t = np.array(ys, dtype=np.uint32)
        gstats = {}
        for n in (2, 4, 8):
            gn = [int(v) for v in gn_table(t, n)]
            gstats[n] = interpolant_stats(gn)
        interp[name]["G_n"] = gstats
        log(f"  G_n sparsity {[gstats[n]['nonzero'] for n in (2, 4, 8)]}")

        ct = conjugacy_to_translation(ys, deg=6)
        cm = conjugacy_to_multiply(ys, deg=4, alphas=[1, 2, 3, 7, 16, 32, 128, 255])
        cf = is_dickson_or_affine_conj(ys)
        conj[name] = {"translation_deg6": ct, "multiply": cm, "dickson": cf}
        log(
            f"  conj translate={ct['exists_nonconst']} mul_hits={len(cm['hits'])} "
            f"square={cf['affine_conj_to_square']}"
        )

        rk = unfolding_ranks(ys)
        rk["mpo_gf2"] = gf2_unfolding_ranks(ys)
        cur = ys
        fr = []
        for n in (1, 2, 4, 8):
            if n > 1:
                cur = [ys[v] for v in cur]
            tt = np.array(cur, dtype=np.int64).reshape(4, 4, 4, 4)
            fr.append(int(np.linalg.matrix_rank(tt.reshape(16, 16))))
        rk["Fn_value_16x16_rank"] = fr
        gn8 = [int(v) for v in gn_table(np.array(ys, dtype=np.uint32), 8)]
        rk["G8_16x16_rank"] = int(
            np.linalg.matrix_rank(np.array(gn8, dtype=np.int64).reshape(16, 16))
        )
        ranks[name] = rk
        log(f"  ranks {rk}")

        commute[name] = commute_library(ys)
        log(f"  commute {commute[name]}")

        lcs = []
        for x0 in (1, 17, 99):
            seq = []
            u = x0
            for _ in range(80):
                u = ys[u]
                seq.append(u)
            lcs.append(bm_gf256(seq))
        bm[name] = {"lc": lcs, "same": len(set(lcs)) == 1}
        log(f"  BM-GF256 {bm[name]}")

        sc = linear_semiconjugacy(ys)
        semi[name] = sc
        log(f"  semiconj {sc}")

        ch = affine_conj_to_cheap(ys)
        cheap[name] = {"n_hits": len(ch["hits"]), "hits": ch["hits"][:4]}
        log(f"  cheap-conj hits={cheap[name]['n_hits']}")

        dmap = {x0: orbit_and_G_diffs(ys, x0) for x0 in (1, 17, 99)}
        diffs[name] = dmap
        log(f"  diffs {dmap}")

        cy = cycle_type(ys)
        cycles[name] = cy
        log(f"  cycles {cy}")

    log("sandwich HMAC r2/r4/r8")
    sand = {
        f"r{r}": sandwich(4, 2, r, 21) for r in (2, 4, 8)
    }
    for r, s in sand.items():
        log(
            f"  {r} Fn={s['identity_Fn_HO_Q_HI']} "
            f"nz F/Q/HI/HO={s['interp_F']['nonzero']}/"
            f"{s['interp_Q']['nonzero']}/{s['interp_HI']['nonzero']}/"
            f"{s['interp_HO']['nonzero']} "
            f"im F/Q={s['im_F']}/{s['im_Q']} "
            f"Qflag={s['Q_semiconj']['max_flag_height']} "
            f"Fflag={s['F_semiconj']['max_flag_height']}"
        )

    out = {
        "interpolant": interp,
        "conjugacy": conj,
        "ranks": ranks,
        "commute": commute,
        "berlekamp_gf256": bm,
        "semiconjugacy": semi,
        "cheap_affine_conj": cheap,
        "finite_diffs": diffs,
        "cycles": cycles,
        "sandwich": sand,
        "seconds": round(time.time() - t0, 3),
    }
    path = OUT / "novel.json"
    path.write_text(json.dumps(out, indent=2))
    log(f"wrote {path} in {out['seconds']}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
