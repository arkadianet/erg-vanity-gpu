#!/usr/bin/env python3
"""Run the PBKDF2-orbit structure experiments and write results/latest.json."""

from __future__ import annotations

import json
import os
import sys
import time
import traceback

# Allow `python run_all.py` from this directory.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from experiments import run_all  # noqa: E402


class _Enc(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, set):
            return sorted(o)
        if isinstance(o, bytes):
            return o.hex()
        return super().default(o)


def main() -> int:
    t0 = time.time()
    try:
        result = run_all()
    except Exception as e:
        result = {"error": str(e), "trace": traceback.format_exc()}
        print(result["trace"], file=sys.stderr)
        # still write the error so the report can cite it
    result["_elapsed_s"] = round(time.time() - t0, 3)
    out_dir = os.path.join(HERE, "results")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "latest.json")
    with open(path, "w") as f:
        json.dump(result, f, indent=2, cls=_Enc, sort_keys=False)
    print(f"wrote {path} in {result['_elapsed_s']}s")
    if "error" in result:
        return 1
    # Compact stdout summary
    sc = result["selfcheck"]
    print("selfcheck:", {k: sc[k] for k in sc if k != "sha512_2048_budget"})
    print("budget 2048:", sc["sha512_2048_budget"])
    print("symbolic rows:", len(result["symbolic"]))
    for row in result["symbolic"]:
        print(" ", row)
    print("io_coupling extra identities:", result["io_coupling"]["extra_identities_from_real_IO"])
    print("full related:")
    for r in result["full_related"]["reports"]:
        print(" ", r["label"], "eq", r["eq_nonpad_count"], "xorc", r["xor_const_nonzero_count"])
    print("ladder identities that held:")
    for row in result["ladder"]:
        ident = row["identity"]
        print(" ", ident["params"], "->", sorted(ident["true_identities"]))
        if "graph" in row:
            g = row["graph"]
            print(
                "    graph image",
                g.get("image_frac"),
                "cycles",
                g.get("n_cycles"),
                "xor0",
                g.get("all_cycles_xor0"),
                "coboundary",
                g.get("coboundary_V_exists"),
            )
        inv = row["invariants"]
        print("    word_closed", inv.get("per_word_closed"), "lin_inv", inv.get("surviving_linear_invariants"))
    print("quadratic invariants:")
    for row in result.get("quadratic_invariants", []):
        print(" ", row)
    print("DK linear complexity:")
    for row in result.get("dk_linear_complexity", []):
        print(" ", row["params"], "lc", row.get("lc_bit0"), "mean", row.get("lc_mean"))
    print("bitblast:")
    for row in result.get("bitblast", []):
        print(" ", row)
    print("BDD closure:")
    for row in result.get("bdd_closure", []):
        if "rows" in row:
            print(" ", row["params"])
            for r in row["rows"]:
                print("   ", r["kind"], "mean", r["mean"], "max", r["max"])
        else:
            print(" ", row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
