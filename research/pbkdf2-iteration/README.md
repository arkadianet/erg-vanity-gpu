# PBKDF2 iteration algorithm research

Author: arkadianet

Exact-algorithm experiments for

    T = XOR_{i=1}^{n} F^i(x)

where F is HMAC-SHA512 after ipad/opad midstate precomputation (or a
reduced-width model of that map).

This directory does **not** modify the production PBKDF2 implementation
and does not touch GPU kernels.

- `models.py` — function hierarchy from linear maps up to mini-HMAC / invertible ARX-HMAC
- `analyze.py` — Koopman, ANF/degree, conjugacy, closed forms
- `algorithms.py` — cycle prefix-XOR and the order-2 permutation recurrence
- `gf256.py` — GF(256) arithmetic and univariate interpolation
- `run_experiments.py` — first-round equivalence / cost measurements
- `run_novel.py` / `run_quotients.py` / `run_invertible.py` / `run_linstruct.py`
- `RESEARCH_LOG.md` — hypothesis-by-hypothesis log
- `REPORT.md` — findings

```bash
pip install -r requirements.txt
python3 run_experiments.py
python3 run_synthesis.py   # G2 vs 2F SAT + constructive circuits
python3 run_slices.py      # exact 4-var restriction MC
python3 run_novel.py
python3 run_quotients.py
python3 run_invertible.py
python3 run_linstruct.py
python3 run_algorithms.py
```
