#!/usr/bin/env python3
"""Exact-synthesis experiment: Cost(G2) vs Cost(F)+Cost(F∘F).

Target: minihmac_n4b2r4 (w=8, 4 rounds, full degree).
G2 may use arbitrary sharing; it is not forced to be two copies of F.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np

from analyze import algebraic_degree, anf_term_count, build_table, mobius
from circuit import Circuit, build_hmac_family, two_copy_upper_bound, Counts
from models import mini_hmac
from sat_mc import search_mc, verify_mc, solve_mc

HERE = Path(__file__).resolve().parent
OUT = HERE / "results"
OUT.mkdir(exist_ok=True)


def log(msg: str) -> None:
    print(msg, flush=True)


def tables_of(fn_table: np.ndarray, w: int) -> list[list[int]]:
    N = 1 << w
    bits = []
    for b in range(w):
        bits.append([int((int(fn_table[x]) >> b) & 1) for x in range(N)])
    return bits


def bit_degrees(table: np.ndarray, w: int) -> list[int]:
    anf = mobius(table)
    degs = []
    for b in range(w):
        d = 0
        for i, v in enumerate(anf):
            if (int(v) >> b) & 1:
                d = max(d, int(i).bit_count())
        degs.append(d)
    return degs


def gf2_solve(rows: list[list[int]], rhs: list[int]) -> list[int] | None:
    """Solve A x = rhs over GF(2). rows are bit-vectors as 0/1 lists."""
    A = [r[:] + [rhs[i]] for i, r in enumerate(rows)]
    n = len(A)
    m = len(A[0]) - 1
    r = c = 0
    piv = [-1] * m
    while r < n and c < m:
        p = None
        for i in range(r, n):
            if A[i][c]:
                p = i
                break
        if p is None:
            c += 1
            continue
        A[r], A[p] = A[p], A[r]
        piv[c] = r
        for i in range(n):
            if i != r and A[i][c]:
                for j in range(c, m + 1):
                    A[i][j] ^= A[r][j]
        r += 1
        c += 1
    for i in range(n):
        if not any(A[i][:m]) and A[i][m]:
            return None
    x = [0] * m
    for j, pr in enumerate(piv):
        if pr != -1:
            x[j] = A[pr][m]
    return x


def affine_map_exists(src: np.ndarray, dst: np.ndarray, w: int) -> bool:
    """Does dst(x) = M src(x) ⊕ b hold for some M,b?"""
    N = 1 << w
    # unknowns: M (w*w) then b (w). Equation per (x, outbit).
    rows = []
    rhs = []
    # 256*8 = 2048 eqs, 72 unknowns — subsample all, it's fine
    for x in range(N):
        s = int(src[x])
        d = int(dst[x])
        for t in range(w):
            row = [0] * (w * w + w)
            for i in range(w):
                if (s >> i) & 1:
                    row[t * w + i] = 1
            row[w * w + t] = 1
            rows.append(row)
            rhs.append((d >> t) & 1)
    return gf2_solve(rows, rhs) is not None


def affine_plus_x_exists(src: np.ndarray, dst: np.ndarray, w: int) -> bool:
    """dst(x) = M src(x) ⊕ N x ⊕ b."""
    N = 1 << w
    rows = []
    rhs = []
    # M (w*w), N (w*w), b (w)
    nunk = 2 * w * w + w
    for x in range(N):
        s = int(src[x])
        d = int(dst[x])
        for t in range(w):
            row = [0] * nunk
            for i in range(w):
                if (s >> i) & 1:
                    row[t * w + i] = 1
                if (x >> i) & 1:
                    row[w * w + t * w + i] = 1
            row[2 * w * w + t] = 1
            rows.append(row)
            rhs.append((d >> t) & 1)
    return gf2_solve(rows, rhs) is not None


def image_set(table: np.ndarray) -> set[int]:
    return set(int(v) for v in table)


def right_compose_possible(f: np.ndarray, g2: np.ndarray) -> bool:
    """Exists g with F∘g = G2?  Iff im(G2) ⊆ im(F)."""
    return image_set(g2).issubset(image_set(f))


def left_compose_possible(f: np.ndarray, g2: np.ndarray) -> bool:
    """Exists g with g∘F = G2?  Iff F(x)=F(y) ⇒ G2(x)=G2(y)."""
    bucket: dict[int, int] = {}
    for x in range(len(f)):
        fx = int(f[x])
        gx = int(g2[x])
        if fx in bucket and bucket[fx] != gx:
            return False
        bucket[fx] = gx
    return True


def validate_sat() -> dict:
    """MC(x0∧x1∧x2∧x3) = 3; MC(x0⊕x1) = 0."""
    n = 4
    N = 16
    and4 = [[((x >> 0) & (x >> 1) & (x >> 2) & (x >> 3)) & 1 for x in range(N)]]
    xor2 = [[((x >> 0) ^ (x >> 1)) & 1 for x in range(N)]]
    r0 = solve_mc(xor2, n, 0, 5.0)
    r2 = solve_mc(and4, n, 2, 8.0)
    r3 = solve_mc(and4, n, 3, 8.0)
    ok0 = r0.status == "sat" and verify_mc(xor2, n, r0)
    ok2 = r2.status == "unsat"
    ok3 = r3.status == "sat" and verify_mc(and4, n, r3)
    return {
        "xor_mc0": r0.status,
        "xor_verified": ok0,
        "and4_k2": r2.status,
        "and4_k3": r3.status,
        "and4_k2_unsat": ok2,
        "and4_verified": ok3,
        "harness_ok": ok0 and ok2 and ok3,
    }


def constructive(nwords: int, bits: int, rounds: int, seed: int, model) -> dict:
    fam = build_hmac_family(nwords, bits, rounds, seed)
    ckt: Circuit = fam["circuit"]
    w = fam["w"]
    # exhaustive DAG vs concrete F
    eq_f = eq_f2 = eq_g2 = True
    for x in range(1 << w):
        fx = model.f(x)
        f2 = model.f(fx)
        g2 = fx ^ f2
        if ckt.eval_bits(x, fam["f_bits"]) != fx:
            eq_f = False
        if ckt.eval_bits(x, fam["f2_bits"]) != f2:
            eq_f2 = False
        if ckt.eval_bits(x, fam["g2_bits"]) != g2:
            eq_g2 = False
    two = two_copy_upper_bound(fam["counts_F"])
    two.xor += w  # G2 combine
    cF, cG = fam["counts_F"], fam["counts_G2_dag"]
    return {
        "equiv_F": eq_f,
        "equiv_F2": eq_f2,
        "equiv_G2": eq_g2,
        "I": fam["I"],
        "O": fam["O"],
        "counts_F": cF.as_dict(),
        "counts_G2_hashcons": cG.as_dict(),
        "counts_two_copy": two.as_dict(),
        "hashcons_and_vs_two_copy": cG.and_ / max(1, two.and_),
        "hashcons_gates_vs_two_copy": cG.gates / max(1, two.gates),
        "hashcons_weighted_vs_two_copy": cG.weighted_arx / max(1, two.weighted_arx),
        "extra_ands_for_F2": cG.and_ - cF.and_,
        "sharing_saved_ands": two.and_ - cG.and_,
    }


def identities(f: np.ndarray, f2: np.ndarray, g2: np.ndarray, w: int) -> dict:
    N = 1 << w
    return {
        "G2_eq_F": bool(np.array_equal(g2, f)),
        "G2_eq_F2": bool(np.array_equal(g2, f2)),
        "G2_eq_zero": bool(np.all(g2 == 0)),
        "G2_eq_id": bool(all(int(g2[x]) == x for x in range(N))),
        "G2_eq_F_xor_id": bool(all(int(g2[x]) == (int(f[x]) ^ x) for x in range(N))),
        "G2_affine_of_F": affine_map_exists(f, g2, w),
        "G2_affine_of_F2": affine_map_exists(f2, g2, w),
        "G2_affine_of_x": affine_map_exists(np.arange(N, dtype=np.uint32), g2, w),
        "G2_EA_of_F2": affine_plus_x_exists(f2, g2, w),
        "G2_EA_of_F": affine_plus_x_exists(f, g2, w),
        "exists_g_F_after_g": right_compose_possible(f, g2),
        "exists_g_g_after_F": left_compose_possible(f, g2),
        "F_permutation": len(image_set(f)) == N,
        "imF": len(image_set(f)),
        "imG2": len(image_set(g2)),
    }


def mc_block(name: str, table: np.ndarray, w: int, kmin: int, kmax: int, timeout: float) -> dict:
    tabs = tables_of(table, w)
    degs = bit_degrees(table, w)
    log(f"  SAT-MC {name} k={kmin}..{kmax} degs={degs}")
    rows = search_mc(tabs, w, kmin, kmax, timeout)
    verified = None
    if rows and rows[-1].status == "sat":
        verified = verify_mc(tabs, w, rows[-1])
        log(f"    SAT at k={rows[-1].k} verified={verified} xor_est={rows[-1].xor_est}")
    else:
        log(f"    last {rows[-1].status if rows else 'none'} k={rows[-1].k if rows else None}")
    return {
        "bit_degrees": degs,
        "anf_terms": anf_term_count(table, w),
        "vec_degree": algebraic_degree(table),
        "scan": [
            {"k": r.k, "status": r.status, "seconds": r.seconds, "xor_est": r.xor_est}
            for r in rows
        ],
        "and_lower_bound": (
            max(r.k for r in rows if r.status == "unsat") + 1
            if any(r.status == "unsat" for r in rows)
            else None
        ),
        "and_upper_from_sat": rows[-1].k if rows and rows[-1].status == "sat" else None,
        "verified": verified,
        "last_status": rows[-1].status if rows else None,
    }


def per_bit_mc(table: np.ndarray, w: int, bits: list[int], kmax: int, timeout: float) -> dict:
    degs = bit_degrees(table, w)
    out = {}
    tabs_all = tables_of(table, w)
    for b in bits:
        kmin = max(0, degs[b] - 1)
        log(f"    bit {b} deg={degs[b]} k={kmin}..{kmax}")
        rows = search_mc([tabs_all[b]], w, kmin, kmax, timeout)
        sat = next((r for r in rows if r.status == "sat"), None)
        unsat_max = max((r.k for r in rows if r.status == "unsat"), default=kmin - 1)
        rec = {
            "deg": degs[b],
            "scan": [{"k": r.k, "status": r.status, "seconds": r.seconds} for r in rows],
            "unsat_upto": unsat_max if unsat_max >= kmin else None,
            "sat_at": sat.k if sat else None,
            "verified": verify_mc([tabs_all[b]], w, sat) if sat else None,
        }
        out[str(b)] = rec
        log(f"      unsat_upto={rec['unsat_upto']} sat_at={rec['sat_at']}")
    return out


def main() -> int:
    nwords, bits, rounds, seed = 4, 2, 4, 21
    model = mini_hmac(nwords, bits, rounds, seed=seed)
    w = model.w
    log(f"=== exact synthesis {model.name} w={w} ===")
    t0 = time.time()

    log("SAT harness")
    harness = validate_sat()
    log(f"  harness_ok={harness['harness_ok']} {harness}")
    if not harness["harness_ok"]:
        log("SAT harness failed; aborting interpretation")
        return 1

    log("constructive DAG")
    cons = constructive(nwords, bits, rounds, seed, model)
    log(
        f"  DAG equiv F/F2/G2={cons['equiv_F']}/{cons['equiv_F2']}/{cons['equiv_G2']}"
    )
    log(f"  F ands={cons['counts_F']['and']} gates={cons['counts_F']['gates']}")
    log(
        f"  G2 hash-cons ands={cons['counts_G2_hashcons']['and']} "
        f"two-copy ands={cons['counts_two_copy']['and']} "
        f"ratio={cons['hashcons_and_vs_two_copy']:.4f}"
    )

    log("truth tables")
    f = build_table(model)
    f2 = f[f]
    g2 = f ^ f2
    log(f"  deg F/F2/G2={algebraic_degree(f)}/{algebraic_degree(f2)}/{algebraic_degree(g2)}")
    log(f"  bitdeg F={bit_degrees(f, w)} F2={bit_degrees(f2, w)} G2={bit_degrees(g2, w)}")

    log("algebraic identities")
    ident = identities(f, f2, g2, w)
    log(f"  {ident}")

    # Vectorial MC: start at the degree lower bound.
    # Timeouts are "not found". UNSAT is a lower bound.
    timeout = 40.0
    log("vectorial MC")
    mc_f = mc_block("F", f, w, kmin=5, kmax=14, timeout=timeout)
    mc_f2 = mc_block("F2", f2, w, kmin=7, kmax=14, timeout=timeout)
    mc_g2 = mc_block("G2", g2, w, kmin=7, kmax=14, timeout=timeout)

    log("per-bit MC (bits 0,1,4,7)")
    pb_f = per_bit_mc(f, w, [0, 1, 4, 7], kmax=12, timeout=25.0)
    pb_f2 = per_bit_mc(f2, w, [0, 1, 4, 7], kmax=12, timeout=25.0)
    pb_g2 = per_bit_mc(g2, w, [0, 1, 4, 7], kmax=12, timeout=25.0)

    out = {
        "target": model.name,
        "w": w,
        "harness": harness,
        "constructive": cons,
        "degrees": {
            "F": algebraic_degree(f),
            "F2": algebraic_degree(f2),
            "G2": algebraic_degree(g2),
            "F_bits": bit_degrees(f, w),
            "F2_bits": bit_degrees(f2, w),
            "G2_bits": bit_degrees(g2, w),
        },
        "identities": ident,
        "mc_vectorial": {"F": mc_f, "F2": mc_f2, "G2": mc_g2},
        "mc_per_bit": {"F": pb_f, "F2": pb_f2, "G2": pb_g2},
        "seconds": round(time.time() - t0, 3),
    }
    path = OUT / "synthesis.json"
    path.write_text(json.dumps(out, indent=2))
    log(f"wrote {path} in {out['seconds']}s")
    _verdict(out)
    return 0


def _verdict(out: dict) -> None:
    log("\n=== SYNTHESIS VERDICT ===")
    c = out["constructive"]
    log(
        f"constructive AND: F={c['counts_F']['and']}  "
        f"G2-hashcons={c['counts_G2_hashcons']['and']}  "
        f"2F+xor={c['counts_two_copy']['and']}  "
        f"ratio={c['hashcons_and_vs_two_copy']:.3f}"
    )
    for name in ("F", "F2", "G2"):
        b = out["mc_vectorial"][name]
        log(
            f"  {name}: deg={b['vec_degree']} SAT-MC last={b['last_status']} "
            f"lb={b['and_lower_bound']} ub={b['and_upper_from_sat']}"
        )


if __name__ == "__main__":
    sys.exit(main())
