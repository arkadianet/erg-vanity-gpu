#!/usr/bin/env python3
"""Invertible HMAC stand-in and the order-2 (Chebyshev-style) recurrence.

SHA-512 compression is Davies–Meyer around SHACAL-2, a permutation of the
block. So real F = H_O ∘ H_I is a permutation of 64-byte strings.
Reduced Ch/Maj models lose that. This file uses two-key ARX, which stays
bijective, and tests the exact identity

    F^{n+1}(x) ⊕ F^{n-1}(x) = Q(F^n(x)),   Q = F ⊕ F^{-1}

If Q is cheaper than F (especially if Q is affine), iterating and XOR-of
iterates become a linear recurrence of order 2.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np

from analyze import algebraic_degree, gn_table
from models import arx_hmac, arx_map, linear_map
from run_novel import (
    affine_conj_to_cheap,
    conjugacy_to_multiply,
    conjugacy_to_translation,
    interpolant_stats,
    is_dickson_or_affine_conj,
    linear_semiconjugacy,
    table_list,
)

HERE = Path(__file__).resolve().parent
OUT = HERE / "results"


def log(msg: str) -> None:
    print(msg, flush=True)


def is_affine(ys: list[int]) -> bool:
    """F(x⊕y) ⊕ F(0) == F(x) ⊕ F(y) ⊕ F(0) and check via degree."""
    t = np.array(ys, dtype=np.uint32)
    return algebraic_degree(t) <= 1


def cycle_xor_gn(ys: list[int], x: int, n: int) -> int:
    """Exact G_n via one orbit + prefix XOR. O(L) F-lookups, L = orbit size."""
    # walk until repeat of start-of-cycle; we just walk until we see x again
    # or hit n, recording prefix.
    seen = {x: 0}
    pref = [0]  # pref[k] = XOR of first k iterates, pref[0]=0
    u = x
    for i in range(1, n + 1):
        u = ys[u]
        pref.append(pref[-1] ^ u)
        if u in seen:
            # cycle detected at step i, previous occurrence seen[u]
            # For a permutation the first repeat of a *state* closes the orbit
            # of x if we started recording from x (not in pref as a value).
            break
        seen[u] = i
    else:
        return pref[n]
    # u was seen at step p, now at i. Cycle length L = i-p.
    # Careful: `x` itself is the pre-image start, not an iterate.
    # iterates: pref[1]=F(x), ..., pref[i]=F^i(x)=F^p(x)
    p = seen[u]
    L = i - p
    # F^k for k>=p is periodic with period L
    # G_n = pref[n] if n <= i, else pref[p] ⊕ (q copies of cycle xor) ⊕ tail
    if n <= i:
        return pref[n]
    cyc = pref[p + L] ^ pref[p]  # XOR of F^{p+1} .. F^{p+L}
    # wait pref[p+L] ^ pref[p] = XOR of iterates p+1 .. p+L
    remain = n - p
    q, r = divmod(remain, L)
    acc = pref[p]
    if q & 1:
        acc ^= cyc
    acc ^= pref[p + r] ^ pref[p]
    return acc


def verify_cycle_xor(ys: list[int], n: int = 2048, samples: int = 16) -> bool:
    t = np.array(ys, dtype=np.uint32)
    naive = gn_table(t, n)
    for x in range(0, 256, max(1, 256 // samples)):
        if cycle_xor_gn(ys, int(x), n) != int(naive[x]):
            return False
    return True


def integer_abel(ys: list[int], deg: int) -> dict:
    """Exists integer poly ψ of deg≤d with ψ(F(x)) ≡ ψ(x)+1 (mod 256)?

    Linear in the unknown coefficients; solve over Z/256 (not a field —
    try lift via odd-leading or exhaustive for deg≤2).
    """
    # For deg 1: a F+b = a x + b + 1 => a(F-x)=1, F-x constant invertible.
    if deg >= 1:
        diffs = [(ys[x] - x) & 255 for x in range(256)]
        if len(set(diffs)) == 1 and diffs[0] & 1:
            return {"deg": 1, "exists": True, "reason": "F(x)=x+odd"}
    if deg >= 2:
        # ψ = a x^2 + b x + c; c cancels. a F^2+b F = a x^2 + b x + 1
        # brute a,b
        for a in range(256):
            for b in range(256):
                ok = True
                for x in range(256):
                    fx = ys[x]
                    lhs = (a * fx * fx + b * fx) & 255
                    rhs = (a * x * x + b * x + 1) & 255
                    if lhs != rhs:
                        ok = False
                        break
                if ok and (a or b):
                    return {"deg": 2, "exists": True, "a": a, "b": b}
    return {"deg": deg, "exists": False}


def analyze_perm(name: str, ys: list[int], yinv: list[int] | None) -> dict:
    log(f"-- {name}")
    out: dict = {
        "bijective": len(set(ys)) == 256,
        "interp_F": interpolant_stats(ys),
        "deg_F": algebraic_degree(np.array(ys, dtype=np.uint32)),
        "semiconj": linear_semiconjugacy(ys),
        "abel_gf": conjugacy_to_translation(ys, 6),
        "abel_z256": integer_abel(ys, 2),
        "schroeder": conjugacy_to_multiply(ys, 4, [1, 2, 3, 7]),
        "dickson": is_dickson_or_affine_conj(ys),
        "cheap_conj": affine_conj_to_cheap(ys),
    }
    out["abel_gf_nonconst"] = out["abel_gf"]["exists_nonconst"]
    # filter constant Schröder
    real = []
    for h in out["schroeder"]["hits"]:
        if any(h["sample"][1:]):
            real.append(h)
    out["schroeder_nonconst"] = real

    if yinv is not None:
        q = [ys[y] ^ yinv[y] for y in range(256)]
        # Chebyshev identity on all x: F(F(x)) ⊕ x == Q(F(x))
        cheb = all((ys[ys[x]] ^ x) == q[ys[x]] for x in range(256))
        out["Q"] = {
            "interp": interpolant_stats(q),
            "deg": algebraic_degree(np.array(q, dtype=np.uint32)),
            "affine": is_affine(q),
            "chebyshev_identity": cheb,
            "Q_eq_F": q == ys,
            "Q_eq_0": all(v == 0 for v in q),
        }
        # iterate via Q and compare G_n
        # u0 unused; u1=F(x), u2=F2, then u_{k+1}=Q(u_k)⊕u_{k-1}
        def gn_via_q(x: int, n: int) -> int:
            if n == 0:
                return 0
            um1 = x
            u = ys[x]
            acc = u
            for _ in range(2, n + 1):
                nxt = q[u] ^ um1
                acc ^= nxt
                um1, u = u, nxt
            return acc

        t = np.array(ys, dtype=np.uint32)
        naive4 = gn_table(t, 4)
        naive64 = gn_table(t, 64)
        out["Q"]["G4_ok"] = all(gn_via_q(x, 4) == int(naive4[x]) for x in range(256))
        out["Q"]["G64_ok"] = all(gn_via_q(x, 64) == int(naive64[x]) for x in range(256))
        log(
            f"  Q deg={out['Q']['deg']} aff={out['Q']['affine']} "
            f"cheb={cheb} nzF/Q={out['interp_F']['nonzero']}/{out['Q']['interp']['nonzero']}"
        )
    out["cycle_xor_2048_ok"] = verify_cycle_xor(ys, 2048, 32)
    log(
        f"  bij={out['bijective']} degF={out['deg_F']} nz={out['interp_F']['nonzero']} "
        f"Tflag={out['semiconj']['max_flag_height']} abelZ={out['abel_z256']['exists']} "
        f"cycxor={out['cycle_xor_2048_ok']}"
    )
    return out


def main() -> int:
    t0 = time.time()
    log("=== invertible models + order-2 recurrence ===")

    # Control: linear is a permutation; Q should be affine
    lin = linear_map(8, seed=11)
    ys = table_list(lin)
    # inverse table
    yinv = [0] * 256
    for x, y in enumerate(ys):
        yinv[y] = x
    results = {"linear": analyze_perm("linear", ys, yinv)}

    # Pure ARX
    for rounds in (2, 4, 8):
        m = arx_map(4, 2, rounds, seed=4)
        ys = table_list(m)
        yinv = [0] * 256
        ok = True
        try:
            for x, y in enumerate(ys):
                yinv[y] = x
            if len(set(ys)) != 256:
                ok = False
        except Exception:
            ok = False
        name = f"arx_r{rounds}"
        results[name] = analyze_perm(name, ys, yinv if ok else None)
        results[name]["built_inv_from_table"] = ok

    # Two-key ARX HMAC + true inverse circuit
    for rounds in (2, 4, 8):
        parts = arx_hmac(4, 2, rounds, seed=21)
        ys = table_list(parts["F"])
        yinv = table_list(parts["F_inv"])
        # verify inverse
        inv_ok = all(yinv[ys[x]] == x and ys[yinv[x]] == x for x in range(256))
        name = f"arxhmac_r{rounds}"
        results[name] = analyze_perm(name, ys, yinv if inv_ok else None)
        results[name]["circuit_inv_ok"] = inv_ok
        # primitive cost of F vs F_inv vs Q-as-two-evals
        cf = parts["F"].cost_of_f(1)
        ci = parts["F_inv"].cost_of_f(1)
        results[name]["cost_F"] = cf.__dict__
        results[name]["cost_Finv"] = ci.__dict__
        results[name]["cost_Q_as_F_xor_Finv"] = cf.total + ci.total
        log(f"  costs F={cf.total} Finv={ci.total} Q<= {cf.total + ci.total}")

    path = OUT / "invertible.json"
    path.write_text(json.dumps(results, indent=2, default=int))
    log(f"wrote {path} in {round(time.time() - t0, 3)}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
