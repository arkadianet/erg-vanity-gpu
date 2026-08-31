"""GF(2^8) arithmetic and univariate interpolation (AES polynomial)."""

from __future__ import annotations


def mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def pow_gf(a: int, e: int) -> int:
    r = 1
    while e:
        if e & 1:
            r = mul(r, a)
        a = mul(a, a)
        e >>= 1
    return r


def inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError
    return _INV[a]


# inv(0) unused; inv[i] = i^{254}
_INV = [0] * 256
for _i in range(1, 256):
    _INV[_i] = pow_gf(_i, 254)


def interpolate(ys: list[int]) -> list[int]:
    """Monomial coefficients of the unique deg<256 interpolant. ys[x]=f(x).

    Newton form at nodes 0..255, then convert to monomials. O(n^2).
    """
    n = 256
    dd = [ys[i] & 0xFF for i in range(n)]
    for i in range(1, n):
        for j in range(n - 1, i - 1, -1):
            dd[j] = mul(dd[j] ^ dd[j - 1], _INV[j ^ (j - i)])
    # Newton → monomial: poly ← 0; for i=n-1..0: poly ← poly·(x ⊕ i) ⊕ dd[i]
    coef = [0] * n
    for i in range(n - 1, -1, -1):
        nxt = [0] * n
        for k, a in enumerate(coef):
            if not a:
                continue
            nxt[k] ^= mul(a, i)
            if k + 1 < n:
                nxt[k + 1] ^= a
        nxt[0] ^= dd[i]
        coef = nxt
    return coef


def sparsity(coeffs: list[int]) -> dict:
    nz = [(i, c) for i, c in enumerate(coeffs) if c]
    frobenius = {1, 2, 4, 8, 16, 32, 64, 128}
    return {
        "nonzero": len(nz),
        "max_deg": max((i for i, _ in nz), default=0),
        "linearized_terms": sum(1 for i, _ in nz if i in frobenius or i == 0),
        "non_linearized": sum(1 for i, _ in nz if i not in frobenius and i != 0),
        "support_sample": [i for i, _ in nz[:16]],
    }


def eval_poly(coeffs: list[int], x: int) -> int:
    y = 0
    p = 1
    for c in coeffs:
        if c:
            y ^= mul(c, p)
        p = mul(p, x)
    return y
