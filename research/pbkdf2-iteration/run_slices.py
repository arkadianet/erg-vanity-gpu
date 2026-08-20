#!/usr/bin/env python3
"""Exact multiplicative complexity of 4-variable restrictions.

Every 4-var Boolean function has MC ≤ 3, so SAT finishes. The max MC
over restrictions is a lower bound on the parent bit, and the histogram
compares whether G2 restrictions are easier than F / F2 / H.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from itertools import combinations
from pathlib import Path

import numpy as np

from analyze import build_table
from models import mini_hmac
from sat_mc import _solve_mc_inner, verify_mc

HERE = Path(__file__).resolve().parent
OUT = HERE / "results"


def log(msg: str) -> None:
    print(msg, flush=True)


def exact_mc1(fn: list[int]) -> dict:
    """Exact MC of one 4-var Boolean function (truth table length 16)."""
    for k in range(0, 5):
        r = _solve_mc_inner([fn], 4, k)
        if r.status == "sat":
            return {
                "mc": k,
                "verified": verify_mc([fn], 4, r),
                "xor_est": r.xor_est,
            }
    return {"mc": None, "status": "unsat_upto_4"}


def restrict_bit(table: np.ndarray, out_bit: int, free: tuple[int, ...], fixed_val: int) -> list[int]:
    fn = []
    for u in range(16):
        x = 0
        fi = 0
        for i in range(8):
            if i in free:
                bit = (u >> fi) & 1
                fi += 1
            else:
                bit = (fixed_val >> i) & 1
            x |= bit << i
        fn.append((int(table[x]) >> out_bit) & 1)
    return fn


def main() -> None:
    model = mini_hmac(4, 2, 4, seed=21)
    f = build_table(model)
    f2 = f[f]
    g2 = f ^ f2
    hx = np.arange(256, dtype=np.uint32) ^ f
    maps = {"F": f, "H": hx, "F2": f2, "G2": g2}

    # Sanity: 4-var x0∧x1 has MC=1.
    chk = exact_mc1([((x >> 0) & 1) & ((x >> 1) & 1) for x in range(16)])
    log(f"sanity x0∧x1 MC={chk}")
    assert chk["mc"] == 1 and chk["verified"]

    t0 = time.time()
    out: dict = {"sanity": chk, "maps": {}}

    subsets = list(combinations(range(8), 4))
    for mname, tab in maps.items():
        hist = Counter()
        max_mc = [0] * 8
        # also compare paired (F vs G2) later
        for b in range(8):
            for free in subsets:
                rec = exact_mc1(restrict_bit(tab, b, free, 0))
                mc = rec["mc"] if rec["mc"] is not None else -1
                hist[mc] += 1
                if mc > max_mc[b]:
                    max_mc[b] = mc
        out["maps"][mname] = {"max_mc_per_bit": max_mc, "hist": {str(k): v for k, v in sorted(hist.items())}}
        log(f"{mname}: max_mc_bits={max_mc} hist={dict(hist)} n={sum(hist.values())}")

    # Pairwise: for each (bit, subspace), MC(G2) vs MC(F) and MC(F2).
    pair_hist = Counter()
    less_than_two_f = 0
    less_than_f2 = 0
    n_pairs = 0
    for b in range(8):
        for free in subsets:
            mf = exact_mc1(restrict_bit(f, b, free, 0))["mc"]
            mg = exact_mc1(restrict_bit(g2, b, free, 0))["mc"]
            m2 = exact_mc1(restrict_bit(f2, b, free, 0))["mc"]
            pair_hist[(mf, mg, m2)] += 1
            n_pairs += 1
            if mf is not None and mg is not None and mg < 2 * mf:
                less_than_two_f += 1
            if m2 is not None and mg is not None and mg < m2:
                less_than_f2 += 1

    out["pairs"] = {
        "n": n_pairs,
        "G2_lt_2F": less_than_two_f,
        "G2_lt_F2": less_than_f2,
        "hist_F_G2_F2": {f"{a}_{b}_{c}": n for (a, b, c), n in pair_hist.most_common(20)},
    }
    log(f"pairs n={n_pairs} G2<2F={less_than_two_f} G2<F2={less_than_f2}")
    log(f"common (F,G2,F2) MC triples: {pair_hist.most_common(8)}")

    out["seconds"] = round(time.time() - t0, 3)
    path = OUT / "synthesis_slices.json"
    path.write_text(json.dumps(out, indent=2))
    log(f"wrote {path} in {out['seconds']}s")


if __name__ == "__main__":
    main()
