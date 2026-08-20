#!/usr/bin/env python3
"""Exact linear structures of F and of G_n.

A nonzero Δ is a linear structure of H if H(x⊕Δ)⊕H(x) is constant.
Affine maps have this for every Δ. A linear structure of G_n that F
does not have would be a property of the XOR-of-iterates, and would
cut the state space for computing T.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np

from analyze import build_table, gn_table
from models import arx_hmac, mini_hmac
from run_novel import table_list

HERE = Path(__file__).resolve().parent
OUT = HERE / "results"


def log(msg: str) -> None:
    print(msg, flush=True)


def linear_structures(ys: list[int]) -> dict:
    N = len(ys)
    hits = []
    # also count "almost": D_Δ takes few values
    min_image = N
    best_delta = 1
    for d in range(1, N):
        vals = set()
        for x in range(N):
            vals.add(ys[x] ^ ys[x ^ d])
            if len(vals) > min_image and len(vals) > 4:
                # can't be a hit; can still update min later if we break early
                # only skip remaining x if already worse than current min and >1
                if len(vals) >= min_image and len(vals) > 8:
                    break
        nval = len(vals)
        if nval < min_image:
            min_image = nval
            best_delta = d
        if nval == 1:
            hits.append(d)
            if len(hits) >= 12:
                break
    return {
        "n_linear_structures": len(hits),
        "sample": hits[:8],
        "min_derivative_image": min_image,
        "best_delta": best_delta,
    }


def main() -> int:
    t0 = time.time()
    log("=== linear structures of F and G_n ===")
    out = {}

    specs = [
        ("minihmac_r2", table_list(mini_hmac(4, 2, 2, seed=21))),
        ("minihmac_r4", table_list(mini_hmac(4, 2, 4, seed=21))),
        ("minihmac_r8", table_list(mini_hmac(4, 2, 8, seed=21))),
        ("arxhmac_r4", table_list(arx_hmac(4, 2, 4, seed=21)["F"])),
        ("arxhmac_r8", table_list(arx_hmac(4, 2, 8, seed=21)["F"])),
    ]
    for name, ys in specs:
        log(f"-- {name}")
        t = np.array(ys, dtype=np.uint32)
        row = {"F": linear_structures(ys)}
        log(f"  F {row['F']}")
        for n in (2, 4, 8, 16, 2048):
            gn = [int(v) for v in gn_table(t, n)]
            row[f"G{n}"] = linear_structures(gn)
            log(f"  G{n} {row[f'G{n}']}")
        out[name] = row

    # 12-bit F only (G_n tables are fine at 4096)
    log("-- minihmac 4x3 r4 w=12")
    ys12 = table_list(mini_hmac(4, 3, 4, seed=21))
    out["minihmac_b3r4"] = {"F": linear_structures(ys12), "N": 4096}
    log(f"  F {out['minihmac_b3r4']['F']}")
    g2 = [int(v) for v in gn_table(np.array(ys12, dtype=np.uint32), 2)]
    out["minihmac_b3r4"]["G2"] = linear_structures(g2)
    log(f"  G2 {out['minihmac_b3r4']['G2']}")

    path = OUT / "linstruct.json"
    path.write_text(json.dumps(out, indent=2))
    log(f"wrote {path} in {round(time.time()-t0,3)}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
