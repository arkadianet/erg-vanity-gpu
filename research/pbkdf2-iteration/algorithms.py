"""Exact algorithms for G_n = XOR_{i=1}^n F^i that are not 'run F n times'.

Each routine is proven equivalent to the naive walk on the class of F
it claims to handle. None of them is cheaper than n×F for mixed
HMAC-like F at cryptographic width; they exist so the identities can
be differential-tested rather than discussed.
"""

from __future__ import annotations

from models import Model, xor_iterates


def gn_naive(model: Model, x: int, n: int) -> int:
    return xor_iterates(model, x, n)


def gn_cycle_xor(model: Model, x: int, n: int) -> tuple[int, int]:
    """Prefix-XOR on the orbit of x. Returns (G_n(x), F-evals).

    Let the functional graph from x be a tail of length p into a cycle
    of length L. After p+L evaluations the rest of the XOR is
    q copies of the cycle-XOR (which vanish in char 2 when q is even)
    plus a tail of length r. Exact for every map, permutation or not.

    F-evals = min(n, p+L). Beats n iff the orbit closes before n.
    For a random permutation that is typical only when 2^{w/2} ≲ n.
    """
    if n <= 0:
        return 0, 0
    seen = {x: 0}
    pref = [0]
    u = x
    evals = 0
    for i in range(1, n + 1):
        u = model.f(u)
        evals += 1
        pref.append(pref[-1] ^ u)
        if u in seen:
            p = seen[u]
            L = i - p
            if n <= i:
                return pref[n], evals
            cyc = pref[p + L] ^ pref[p]
            remain = n - p
            q, r = divmod(remain, L)
            acc = pref[p]
            if q & 1:
                acc ^= cyc
            acc ^= pref[p + r] ^ pref[p]
            return acc, evals
        seen[u] = i
    return pref[n], evals


def gn_order2(f, finv, x: int, n: int) -> int:
    """G_n via the Chebyshev-style recurrence of a permutation.

    Proof: Q(y) := F(y) ⊕ F^{-1}(y). For y = F^k(x),
    Q(F^k(x)) = F^{k+1}(x) ⊕ F^{k-1}(x). Hence
        F^{k+1}(x) = Q(F^k(x)) ⊕ F^{k-1}(x).
    Seed with (x, F(x)) and walk. Still n-1 applications of Q after
    the first F. Cheaper than n×F iff Cost(Q) < Cost(F), or Q affine
    (then the 2w-bit state is an affine map and G_n is O(w^3 log n)).
    """
    if n <= 0:
        return 0
    um1 = x
    u = f(x)
    acc = u
    for _ in range(2, n + 1):
        q = f(u) ^ finv(u)
        nxt = q ^ um1
        acc ^= nxt
        um1, u = u, nxt
    return acc


def q_map(f, finv, y: int) -> int:
    return f(y) ^ finv(y)
