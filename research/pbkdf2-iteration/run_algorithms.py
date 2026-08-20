#!/usr/bin/env python3
"""Differential-test the exact algorithms against the naive walk."""

from __future__ import annotations

import json
import time
from pathlib import Path

from algorithms import gn_cycle_xor, gn_naive, gn_order2
from models import arx_hmac, linear_map, mini_hmac

HERE = Path(__file__).resolve().parent
OUT = HERE / "results"


def log(msg: str) -> None:
    print(msg, flush=True)


def main() -> int:
    t0 = time.time()
    out: dict = {}

    # cycle-XOR vs naive, several n, several models
    cases = []
    lin = linear_map(8, seed=11)
    mh = mini_hmac(4, 2, 4, seed=21)
    ah = arx_hmac(4, 2, 4, seed=21)["F"]
    for name, m in (("linear8", lin), ("minihmac_r4", mh), ("arxhmac_r4", ah)):
        ok = True
        ev = []
        for n in (1, 2, 7, 9, 16, 64, 2048):
            for x in (0, 1, 17, 99, 200):
                naive = gn_naive(m, x, n)
                got, e = gn_cycle_xor(m, x, n)
                if got != naive:
                    ok = False
                ev.append(e)
        cases.append({"model": name, "ok": ok, "evals_sample": ev[:7]})
        log(f"cycle-xor {name} ok={ok}")
    out["cycle_xor"] = cases

    # order-2 on permutations
    parts = arx_hmac(4, 2, 4, seed=21)
    f, finv = parts["F"].f, parts["F_inv"].f
    ok = True
    for n in (1, 2, 5, 16, 64, 256):
        for x in (0, 1, 17, 99):
            if gn_order2(f, finv, x, n) != gn_naive(parts["F"], x, n):
                ok = False
    out["order2_arxhmac_r4"] = ok
    log(f"order2 arxhmac_r4 ok={ok}")

    lin = linear_map(8, seed=11)
    ys = [lin.f(x) for x in range(256)]
    yinv = [0] * 256
    for x, y in enumerate(ys):
        yinv[y] = x
    ok = True
    for n in (1, 8, 64, 2048):
        for x in (0, 3, 17):
            if gn_order2(lin.f, lambda z: yinv[z], x, n) != gn_naive(lin, x, n):
                ok = False
    out["order2_linear"] = ok
    log(f"order2 linear ok={ok}")

    # width scaling of cycle close-in: does the orbit close before n=2048?
    from models import arx_hmac as AH

    close = {}
    for bits in (2, 4, 8):
        m = AH(4, bits, 4, seed=21)["F"]
        closes = 0
        evals = []
        xs = [1, 17, 99, 12345, 99991]
        for x in xs:
            _, e = gn_cycle_xor(m, x, 2048)
            evals.append(e)
            if e < 2048:
                closes += 1
        close[f"w{m.w}"] = {"closed_before_2048": closes, "n_x": len(xs), "evals": evals}
        log(f"orbit-close w={m.w} {close[f'w{m.w}']}")
    out["orbit_close"] = close
    out["seconds"] = round(time.time() - t0, 3)

    path = OUT / "algorithms.json"
    path.write_text(json.dumps(out, indent=2))
    log(f"wrote {path}")
    return 0 if all(c["ok"] for c in cases) and out["order2_arxhmac_r4"] and out["order2_linear"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
