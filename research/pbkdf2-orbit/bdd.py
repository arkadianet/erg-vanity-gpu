"""ROBDD for n-bit maps, n <= 16.

Used to test iteration-closure: if the BDD of F^n or of the orbit XOR
stays compact as n grows, F^n has a representation that is not 'walk
the orbit'. Growth with width is the survival test.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Callable, Dict, List, Tuple


class BDD:
    def __init__(self, nvars: int):
        self.nvars = nvars
        # node id -> (var, lo, hi)  var in 0..nvars-1, then terminals
        self.FALSE = 0
        self.TRUE = 1
        self._nodes: Dict[Tuple[int, int, int], int] = {}
        self._tab: List[Tuple[int, int, int]] = [(0, 0, 0), (1, 1, 1)]

    def mk(self, v: int, lo: int, hi: int) -> int:
        if lo == hi:
            return lo
        key = (v, lo, hi)
        i = self._nodes.get(key)
        if i is not None:
            return i
        i = len(self._tab)
        self._tab.append(key)
        self._nodes[key] = i
        return i

    def size(self, root: int) -> int:
        seen = set()

        def walk(u: int) -> None:
            if u <= 1 or u in seen:
                return
            seen.add(u)
            v, lo, hi = self._tab[u]
            walk(lo)
            walk(hi)

        walk(root)
        return len(seen) + (0 if root <= 1 else 0) + (1 if root <= 1 else 0)

    def from_truth(self, bitfn: Callable[[int], int]) -> int:
        """bitfn(x) -> 0/1, x in 0..2^n-1. Build ROBDD by Shannon expansion."""
        n = self.nvars

        @lru_cache(None)
        def rec(x_prefix: int, filled: int, v: int) -> int:
            if v == n:
                return self.TRUE if bitfn(x_prefix) else self.FALSE
            # unset bits above v stay 0 in x_prefix until set
            lo = rec(x_prefix, filled, v + 1)
            hi = rec(x_prefix | (1 << v), filled | (1 << v), v + 1)
            return self.mk(v, lo, hi)

        return rec(0, 0, 0)


def map_bdds(fn: Callable[[int], int], bits: int) -> Tuple[BDD, List[int]]:
    bdd = BDD(bits)
    roots = []
    # Build one BDD per output bit from the truth table of `fn`.
    # For bits<=16 this is 2^bits evaluations, shared across bits.
    N = 1 << bits
    table = [fn(i) for i in range(N)]
    for b in range(bits):
        def bitfn(x: int, b=b) -> int:
            return (table[x] >> b) & 1

        # drop lru cache identity by new BDD method each time
        bdd2 = BDD(bits)
        # use a dedicated builder that uses the table
        roots.append(_from_table(bdd, table, b, bits))
        del bdd2
    return bdd, roots


def _from_table(bdd: BDD, table: List[int], bit: int, n: int) -> int:
    @lru_cache(None)
    def rec(prefix: int, v: int) -> int:
        if v == n:
            return bdd.TRUE if ((table[prefix] >> bit) & 1) else bdd.FALSE
        lo = rec(prefix, v + 1)
        hi = rec(prefix | (1 << v), v + 1)
        return bdd.mk(v, lo, hi)

    return rec(0, 0)


def compose_table(fn: Callable[[int], int], bits: int, times: int) -> List[int]:
    N = 1 << bits
    t = [fn(i) for i in range(N)]
    cur = list(range(N))
    for _ in range(times):
        cur = [t[x] for x in cur]
    return cur


def xor_prefix_table(fn: Callable[[int], int], bits: int, n: int) -> List[int]:
    """x -> F(x) XOR ... XOR F^n(x)"""
    N = 1 << bits
    t = [fn(i) for i in range(N)]
    out = [0] * N
    cur = list(range(N))
    for _ in range(n):
        cur = [t[x] for x in cur]
        for i in range(N):
            out[i] ^= cur[i]
    return out


def bdd_sizes_from_table(table: List[int], bits: int) -> dict:
    bdd = BDD(bits)
    sizes = []
    for b in range(bits):
        r = _from_table(bdd, table, b, bits)
        sizes.append(bdd.size(r))
    return {
        "bits": bits,
        "per_bit": sizes,
        "mean": round(sum(sizes) / len(sizes), 2),
        "max": max(sizes),
        "unique_nodes_all_bits": len(bdd._tab) - 2,
    }
