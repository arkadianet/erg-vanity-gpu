#!/usr/bin/env python3
"""Independent exact-algorithm experiments for XOR_{i=1}^n F^i.

Compares every candidate against n × cost(F). A result counts only if it
needs fewer F/HMAC evaluations, fewer compressions, or fewer primitives.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np

from analyze import (
    affine_gn_closed,
    algebraic_degree,
    anf_term_count,
    berlekamp_massey,
    bitperm_tfunction_search,
    build_table,
    check_equiv,
    cycle_stats,
    degree_profile,
    extract_affine,
    gn_table,
    gn_table_doubling,
    hx_vs_f,
    invariant_linear_forms,
    is_affine_table,
    is_tfunction_table,
    iterate_sequence,
    jacobian_constant,
    jacobian_gf2,
    koopman_krylov_ranks,
    linear_complexities,
    naive_cost,
    tfunction_violations,
    walsh_sparsity,
)
from models import (
    Cost,
    Model,
    arx_chmaj_map,
    arx_map,
    iterate,
    linear_map,
    mini_hmac,
    mini_sha,
    quadratic_map,
    tiny_nlr,
    xor_iterates,
)

HERE = Path(__file__).resolve().parent
OUT = HERE / "results"
OUT.mkdir(exist_ok=True)


def log(msg: str) -> None:
    print(msg, flush=True)


def model_catalog() -> list[Model]:
    models = [
        linear_map(8, seed=11),
        quadratic_map(8, seed=12),
        tiny_nlr(8, seed=13),
        arx_map(4, 2, 2, seed=14),
        arx_map(4, 2, 4, seed=15),
        arx_chmaj_map(4, 2, 2, seed=16),
        arx_chmaj_map(4, 2, 4, seed=17),
        mini_sha(4, 2, 2, seed=18),
        mini_sha(4, 2, 4, seed=19),
        mini_hmac(4, 2, 2, seed=20),
        mini_hmac(4, 2, 4, seed=21),
        mini_hmac(4, 3, 2, seed=22),
        mini_hmac(4, 3, 4, seed=23),
        mini_hmac(4, 4, 4, seed=24),
        mini_hmac(8, 2, 4, seed=25),
        mini_hmac(8, 2, 8, seed=26),
    ]
    return models


def table_suite(models: list[Model]) -> dict:
    results = {}
    for m in models:
        if m.w > 16:
            continue
        log(f"  table suite: {m.name} (w={m.w})")
        t0 = time.time()
        table = build_table(m)
        ns = [1, 2, 4, 8]
        if m.w <= 12:
            ns += [16]
        if m.w <= 8:
            ns += [32, 64]

        # doubling equivalence
        eq = []
        for n in ns:
            g1 = gn_table(table, n)
            g2 = gn_table_doubling(table, n)
            eq.append({"n": n, "doubling_equiv": bool(np.array_equal(g1, g2))})

        deg = degree_profile(table, ns, m.w)
        hx = hx_vs_f(table, m.w)
        cyc = cycle_stats(table)
        aff = is_affine_table(table, m.w)
        tf = is_tfunction_table(table, m.w)
        perm_tf = bitperm_tfunction_search(table, m.w, trials=80 if m.w <= 8 else 30)
        walsh = walsh_sparsity(table, m.w)
        inv = invariant_linear_forms(table, m.w) if m.w <= 12 else None
        max_k = min(16, (1 << m.w) // max(1, m.w) + 2)
        if m.w <= 8:
            krylov = koopman_krylov_ranks(table, m.w, max_k)
        elif m.w <= 12:
            krylov = koopman_krylov_ranks(table, m.w, min(8, max_k))
        else:
            krylov = koopman_krylov_ranks(table, m.w, 4)

        # composition ANF: F vs F∘F vs G_2
        ff = table[table]
        g2 = table ^ ff
        composition = {
            "anf_F": anf_term_count(table, m.w),
            "anf_F2": anf_term_count(ff, m.w),
            "anf_G2": anf_term_count(g2, m.w),
            "deg_F": algebraic_degree(table),
            "deg_F2": algebraic_degree(ff),
            "deg_G2": algebraic_degree(g2),
        }

        closed = None
        if aff:
            extracted = extract_affine(table, m.w)
            assert extracted is not None
            A, b = extracted
            closed = []
            for n in [2, 4, 8, 16, 64, 256, 2048]:
                naive = int(gn_table(table, n)[3]) if n <= 64 else xor_iterates(m, 3, n)
                got, ops = affine_gn_closed(A, b, 3, n, m.w)
                closed.append(
                    {
                        "n": n,
                        "equiv": got == naive,
                        "closed_xor_ops_est": ops,
                        "naive_ops": naive_cost(m, n, 3),
                    }
                )

        results[m.name] = {
            "w": m.w,
            "note": m.note,
            "cost_F": m.cost_of_f().total,
            "cost_F_breakdown": m.cost_of_f().__dict__,
            "affine": aff,
            "tfunction": tf,
            "bitperm_tfunction": perm_tf,
            "jacobian_constant": jacobian_constant(m),
            "doubling_equiv": eq,
            "degree": deg,
            "H_vs_F": hx,
            "cycles": cyc,
            "walsh": walsh,
            "invariant_linear_forms": inv,
            "koopman_krylov_ranks": krylov,
            "koopman_saturated": krylov[-1] == krylov[-2] if len(krylov) > 1 else False,
            "koopman_final_rank": krylov[-1],
            "koopman_max_possible": min(len(krylov) * m.w, m.w * (1 << m.w)),
            "composition": composition,
            "affine_closed_form": closed,
            "seconds": round(time.time() - t0, 3),
        }
    return results


def orbit_suite() -> dict:
    """Larger models: single-orbit measurements, n up to 2048."""
    models = [
        mini_hmac(4, 8, 8, seed=31),   # 32-bit
        mini_hmac(8, 8, 8, seed=32),   # 64-bit
        mini_hmac(8, 8, 16, seed=33),  # 64-bit, more rounds
        arx_chmaj_map(8, 8, 8, seed=34),
        tiny_nlr(32, seed=35),
        linear_map(32, seed=36),
    ]
    results = {}
    ns = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048]
    for m in models:
        log(f"  orbit suite: {m.name} (w={m.w})")
        t0 = time.time()
        xs = [1, 0xA5A5A5A5 & ((1 << m.w) - 1), 1234567 & ((1 << m.w) - 1)]
        # equivalence of naive vs itself at several n (sanity) + cost growth
        costs = []
        for n in ns:
            c = Cost()
            xor_iterates(m, xs[0], n, c)
            costs.append({"n": n, "ops": c.total, "ops_over_nF": c.total / (n * m.cost_of_f().total)})

        # linear complexity of iterate bits
        seq = iterate_sequence(m, xs[0], 512)
        lcs = linear_complexities(seq, min(m.w, 16))
        # second start / "key" (different seed model clone not available; different x)
        seq2 = iterate_sequence(m, xs[1], 512)
        lcs2 = linear_complexities(seq2, min(m.w, 16))

        # Jacobian variation along an orbit
        js = [tuple(jacobian_gf2(m, iterate(m, xs[0], i))) for i in range(0, 24)]
        unique_J = len(set(js))

        # 2-adic leakage: low k bits of F(x) vs F(x with high bits cleared)
        twodic = []
        for k in range(1, min(m.w, 16) + 1):
            mask = (1 << k) - 1
            bad = 0
            for x in xs + [0x11, 0x80000001 & ((1 << m.w) - 1)]:
                if (m.f(x) & mask) != (m.f(x & mask) & mask):
                    bad += 1
            twodic.append({"low_bits": k, "mismatches": bad, "trials": 5})

        # even-n identity check: G_n is not (n mod 2)*something
        even_collapse = xor_iterates(m, xs[0], 16) == 0

        results[m.name] = {
            "w": m.w,
            "cost_F": m.cost_of_f().total,
            "cost_growth": costs,
            "linear_complexity_x0": {
                "min": min(lcs),
                "max": max(lcs),
                "mean": sum(lcs) / len(lcs),
                "values": lcs,
            },
            "linear_complexity_x1": {
                "min": min(lcs2),
                "max": max(lcs2),
                "mean": sum(lcs2) / len(lcs2),
            },
            "lc_same_poly": all(
                berlekamp_massey([(s >> b) & 1 for s in seq])
                == berlekamp_massey([(s >> b) & 1 for s in seq2])
                for b in range(min(4, m.w))
            ),
            "unique_jacobians_first_24": unique_J,
            "twodic_lowbit_closed": twodic,
            "G16_zero": even_collapse,
            "tfunction_violations_200": tfunction_violations(m, 200),
            "jacobian_constant": jacobian_constant(m, samples=12),
            "seconds": round(time.time() - t0, 3),
        }
    return results


def linear_control() -> dict:
    """Prove the harness detects a real sublinear algorithm."""
    log("  linear control")
    m = linear_map(16, seed=99)
    table = build_table(m)
    A, b = extract_affine(table, m.w)
    rows = []
    for n in [2, 4, 8, 16, 32, 64, 256, 1024, 2048]:
        naive = xor_iterates(m, 7, n)
        got, ops = affine_gn_closed(A, b, 7, n, m.w)
        rows.append(
            {
                "n": n,
                "equiv": got == naive,
                "closed_ops_est": ops,
                "naive_ops": naive_cost(m, n, 7),
                "ratio": ops / max(1, naive_cost(m, n, 7)),
            }
        )
    return {"model": m.name, "rows": rows}


def semigroup_point_eval_obstruction() -> dict:
    """Doubling of (F^n, G_n) as functions vs as point evaluation.

    Point evaluation of the doubled pair still walks n applications of F.
    Count F-evals required by the recursive pairing without orbit memoization
    vs with memoization.
    """
    def evals_no_memo(n: int) -> int:
        if n == 1:
            return 1
        if n % 2 == 0:
            # G_n(x)=G_{n/2}(x) ⊕ G_{n/2}(F^{n/2}(x)); F^{n/2} also needed
            # naive recursion: two G_{n/2} plus computing F^{n/2} separately
            return 2 * evals_no_memo(n // 2) + n // 2
        return evals_no_memo(n - 1) + 1

    def evals_memo(n: int) -> int:
        return n

    ns = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048]
    return {
        "rows": [
            {
                "n": n,
                "F_evals_no_memo": evals_no_memo(n),
                "F_evals_memo": evals_memo(n),
                "note": "memoized doubling === sequential walk",
            }
            for n in ns
        ]
    }


def hmac_structure_identities() -> dict:
    """Exact identities from Davies-Meyer + even n. Do they cut A/B/C?"""
    m = mini_hmac(4, 4, 4, seed=40)
    # G_n for even n is not zero and not F(x)
    x = 0x5A
    g2 = xor_iterates(m, x, 2)
    g4 = xor_iterates(m, x, 4)
    f1 = m.f(x)
    return {
        "model": m.name,
        "G2_equals_F": g2 == f1,
        "G2_zero": g2 == 0,
        "G4_zero": g4 == 0,
        "G4_equals_G2": g4 == g2,
        "note": "Even-n XOR does not cancel HMAC-like F iterates",
    }


def main() -> int:
    log("=== PBKDF2 iteration algorithm experiments ===")
    t0 = time.time()
    catalog = model_catalog()
    log(f"models: {[m.name for m in catalog]}")

    out = {
        "linear_control": linear_control(),
        "semigroup_point_eval": semigroup_point_eval_obstruction(),
        "hmac_identities": hmac_structure_identities(),
        "table": table_suite(catalog),
        "orbit": orbit_suite(),
    }
    out["elapsed_s"] = round(time.time() - t0, 3)

    path = OUT / "experiments.json"
    path.write_text(json.dumps(out, indent=2))
    log(f"wrote {path} in {out['elapsed_s']}s")
    _print_summary(out)
    return 0


def _print_summary(out: dict) -> None:
    log("\n=== SUMMARY ===")
    lc = out["linear_control"]["rows"]
    log("linear closed form:")
    for r in lc:
        log(f"  n={r['n']:4d} equiv={r['equiv']} ratio={r['ratio']:.4f}")
    log("per-model (table):")
    for name, r in out["table"].items():
        k = r["koopman_krylov_ranks"]
        last_deg = r["degree"][-1] if r["degree"] else {}
        log(
            f"  {name:28s} w={r['w']:2d} aff={r['affine']} T={r['tfunction']} "
            f"krylov={k[0]}->{k[-1]}/{r['koopman_max_possible']} "
            f"degG={last_deg.get('deg_Gn')} degF={last_deg.get('deg_Fn')} "
            f"cancel={last_deg.get('deg_cancelled')}"
        )


if __name__ == "__main__":
    sys.exit(main())
