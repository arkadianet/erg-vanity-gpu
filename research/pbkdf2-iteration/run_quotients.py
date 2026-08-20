#!/usr/bin/env python3
"""Small-support quotients, word cones, and wider-state semiconjugacy.

A k-bit-support Boolean I is a quotient if I(F(x)) is a function of I(x).
A cheap quotient that survives rounds+width is a coordinate in which
iteration (and XOR-of-iterates) drops dimension.
"""

from __future__ import annotations

import itertools
import json
import time
from pathlib import Path

import numpy as np

from analyze import gn_table
from gf256 import interpolate, sparsity
from models import mini_hmac
from run_novel import linear_semiconjugacy, table_list

HERE = Path(__file__).resolve().parent
OUT = HERE / "results"


def log(msg: str) -> None:
    print(msg, flush=True)


def is_bool_quotient(ys: list[int], I) -> bool:
    """I: int -> {0,1}. True iff I∘F factors through I."""
    seen = [-1, -1]
    for x, fx in enumerate(ys):
        a = I(x)
        b = I(fx)
        if seen[a] < 0:
            seen[a] = b
        elif seen[a] != b:
            return False
    return True


def support_quotients(ys: list[int], k: int, w: int = 8) -> dict:
    """Every Boolean function of some k input bits, as a candidate I."""
    hits = []
    nfun = 1 << (1 << k)
    for bits in itertools.combinations(range(w), k):
        for code in range(nfun):
            # skip constants and functions of fewer than k bits
            def I(x, bits=bits, code=code):
                idx = 0
                for i, b in enumerate(bits):
                    idx |= ((x >> b) & 1) << i
                return (code >> idx) & 1

            # skip if I is constant
            vals = {(code >> t) & 1 for t in range(1 << k)}
            if len(vals) < 2:
                continue
            if is_bool_quotient(ys, I):
                hits.append({"bits": bits, "code": code})
                if len(hits) >= 20:
                    return {"k": k, "hits": hits, "stopped": True}
    return {"k": k, "hits": hits, "stopped": False, "n_hits": len(hits)}


def word_dependence(ys: list[int], nwords: int = 4, bits: int = 2) -> dict:
    """Which input-word subsets determine each output word?"""
    mask = (1 << bits) - 1
    out = {}
    for ow in range(nwords):
        # try subsets of input words, smallest first
        found = None
        for sz in range(1, nwords + 1):
            for subset in itertools.combinations(range(nwords), sz):
                ok = True
                # map from selected input words -> output word; detect collision
                seen: dict[int, int] = {}
                for x, fx in enumerate(ys):
                    key = 0
                    for i, iw in enumerate(subset):
                        key |= ((x >> (iw * bits)) & mask) << (i * bits)
                    y = (fx >> (ow * bits)) & mask
                    if key in seen and seen[key] != y:
                        ok = False
                        break
                    seen[key] = y
                if ok:
                    found = subset
                    break
            if found is not None:
                break
        out[ow] = list(found) if found is not None else None
    return out


def avalanche(ys: list[int], w: int = 8) -> list[int]:
    """dep[j] = number of input bits output bit j depends on."""
    dep = [0] * w
    for j in range(w):
        for i in range(w):
            depends = False
            for x in range(len(ys)):
                if ((ys[x] >> j) & 1) != ((ys[x ^ (1 << i)] >> j) & 1):
                    depends = True
                    break
            if depends:
                dep[j] += 1
    return dep


def wider_semiconj() -> dict:
    out = {}
    for bits, rounds in ((3, 3), (3, 4), (4, 3), (4, 4)):
        m = mini_hmac(4, bits, rounds, seed=21)
        w = m.w
        log(f"semiconj minihmac 4x{bits} r{rounds} w={w}")
        ys = table_list(m)
        # 1-bit quotients only (flag extension is costly at 16-bit)
        N = 1 << w
        if w <= 12:
            sc = linear_semiconjugacy(ys, w)
        else:
            # sample 4000 random forms + all single bits + all 2-bit masks
            rng = np.random.default_rng(0)
            forms = list(range(1, w + 1))  # not quite; do 1<<i
            forms = [1 << i for i in range(w)]
            forms += [3 << i for i in range(w - 1)]
            forms += [int(rng.integers(1, N)) for _ in range(4000)]
            par = np.zeros(N, dtype=np.uint8)
            for i in range(1, N):
                par[i] = par[i >> 1] ^ (i & 1)
            t = np.array(ys, dtype=np.uint32)
            n_hits = 0
            sample_hits = []
            for a in forms:
                seen = [-1, -1]
                ok = True
                for v in range(N):
                    xin = int(par[v & a])
                    xout = int(par[int(t[v]) & a])
                    if seen[xin] < 0:
                        seen[xin] = xout
                    elif seen[xin] != xout:
                        ok = False
                        break
                if ok:
                    n_hits += 1
                    sample_hits.append(a)
            sc = {
                "sampled": True,
                "n_tried": len(forms),
                "n_1bit_quotients": n_hits,
                "sample": sample_hits[:8],
            }
        im = len(set(ys))
        sc["image_size"] = im
        sc["N"] = N
        out[f"b{bits}r{rounds}"] = sc
        log(f"  {sc}")
    return out


def main() -> int:
    t0 = time.time()
    log("=== quotients / cones / wider semiconj ===")

    models = {
        "hmac_r2": table_list(mini_hmac(4, 2, 2, seed=21)),
        "hmac_r3": table_list(mini_hmac(4, 2, 3, seed=21)),
        "hmac_r4": table_list(mini_hmac(4, 2, 4, seed=21)),
        "hmac_r8": table_list(mini_hmac(4, 2, 8, seed=21)),
    }

    qres = {}
    for name, ys in models.items():
        log(f"-- {name}")
        q2 = support_quotients(ys, 2)
        q3 = support_quotients(ys, 3)
        wd = word_dependence(ys)
        av = avalanche(ys)
        # G_2048 interpolant (8-bit trap check)
        g2048 = [int(v) for v in gn_table(np.array(ys, dtype=np.uint32), 2048)]
        gsp = sparsity(interpolate(g2048))
        qres[name] = {
            "support2": {"n_hits": len(q2["hits"]), "hits": q2["hits"][:8], "stopped": q2.get("stopped")},
            "support3": {"n_hits": len(q3["hits"]), "hits": q3["hits"][:8], "stopped": q3.get("stopped")},
            "word_dep": wd,
            "avalanche": av,
            "G2048_sparsity": gsp,
            "G2048_constant": len(set(g2048)) == 1,
            "G2048_nuniq": len(set(g2048)),
        }
        log(
            f"  q2={len(q2['hits'])} q3={len(q3['hits'])} "
            f"words={wd} av={av} G2048_nz={gsp['nonzero']} uniq={len(set(g2048))}"
        )

    wider = wider_semiconj()

    out = {"quotients": qres, "wider": wider, "seconds": round(time.time() - t0, 3)}
    path = OUT / "quotients.json"
    path.write_text(json.dumps(out, indent=2))
    log(f"wrote {path} in {out['seconds']}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
