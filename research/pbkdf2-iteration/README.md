# PBKDF2 iteration algorithm research

Author: arkadianet

Exact-algorithm experiments for

    T = XOR_{i=1}^{n} F^i(x)

where F is HMAC-SHA512 after ipad/opad midstate precomputation (or a
reduced-width model of that map).

This directory does **not** modify the production PBKDF2 implementation
and does not touch GPU kernels.

- `models.py` — function hierarchy from linear maps up to mini-HMAC
- `analyze.py` — Koopman, ANF/degree, conjugacy, closed forms
- `run_experiments.py` — equivalence tests and cost/growth measurements
- `REPORT.md` — findings (written after the experiment run)

```bash
python3 run_experiments.py
```
