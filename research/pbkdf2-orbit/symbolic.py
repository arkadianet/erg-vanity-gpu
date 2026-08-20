"""Word-level hash-consed DAG for the HMAC envelope.

This is not CSE of a conventional SHA listing. Nodes are w-bit words.
Construction applies algebraic rewrites (xor/add/rot/and) so that if
F∘F or the two-compression envelope collapses for a structural reason,
the unique-node count drops below two independent copies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from model import (
    HMAC64_BITLEN,
    Params,
    SHA512_H,
    SHA512_K,
    big_sigma0,
    big_sigma1,
    ch,
    k_word,
    maj,
    mask_of,
    rot_r,
    sigma0,
    sigma1,
)


# op: ('const', value) | ('var', name) | ('xor', a, b) | ('and', a, b)
#     | ('or', a, b) | ('not', a) | ('add', a, b) | ('rot', a, n) | ('shr', a, n)
NodeKey = tuple


@dataclass(frozen=True)
class Node:
    key: NodeKey
    bits: int
    nid: int


class Dag:
    def __init__(self, w: int):
        self.w = w
        self.mask = mask_of(w)
        self._nodes: Dict[NodeKey, Node] = {}
        self._order: List[Node] = []
        self._const: Dict[int, Node] = {}
        self._eval_cache: Dict[int, int] = {}

    def __len__(self) -> int:
        return len(self._order)

    def _mk(self, key: NodeKey) -> Node:
        n = self._nodes.get(key)
        if n is not None:
            return n
        n = Node(key=key, bits=self.w, nid=len(self._order))
        self._nodes[key] = n
        self._order.append(n)
        return n

    def c(self, v: int) -> Node:
        v &= self.mask
        n = self._const.get(v)
        if n is None:
            n = self._mk(("const", v))
            self._const[v] = n
        return n

    def var(self, name: str) -> Node:
        return self._mk(("var", name))

    def is_const(self, n: Node) -> bool:
        return n.key[0] == "const"

    def const_val(self, n: Node) -> int:
        return int(n.key[1])

    def xor(self, a: Node, b: Node) -> Node:
        if self.is_const(a) and self.is_const(b):
            return self.c(self.const_val(a) ^ self.const_val(b))
        if self.is_const(a) and self.const_val(a) == 0:
            return b
        if self.is_const(b) and self.const_val(b) == 0:
            return a
        if a.nid == b.nid:
            return self.c(0)
        # commutative unique key
        if a.nid > b.nid:
            a, b = b, a
        return self._mk(("xor", a.nid, b.nid))

    def and_(self, a: Node, b: Node) -> Node:
        if self.is_const(a) and self.is_const(b):
            return self.c(self.const_val(a) & self.const_val(b))
        if self.is_const(a):
            if self.const_val(a) == 0:
                return self.c(0)
            if self.const_val(a) == self.mask:
                return b
        if self.is_const(b):
            if self.const_val(b) == 0:
                return self.c(0)
            if self.const_val(b) == self.mask:
                return a
        if a.nid == b.nid:
            return a
        if a.nid > b.nid:
            a, b = b, a
        return self._mk(("and", a.nid, b.nid))

    def not_(self, a: Node) -> Node:
        if self.is_const(a):
            return self.c((~self.const_val(a)) & self.mask)
        if a.key[0] == "not":
            return self._order[a.key[1]]
        return self._mk(("not", a.nid))

    def add(self, a: Node, b: Node) -> Node:
        if self.is_const(a) and self.is_const(b):
            return self.c((self.const_val(a) + self.const_val(b)) & self.mask)
        if self.is_const(a) and self.const_val(a) == 0:
            return b
        if self.is_const(b) and self.const_val(b) == 0:
            return a
        if a.nid > b.nid:
            a, b = b, a
        return self._mk(("add", a.nid, b.nid))

    def rot(self, a: Node, n: int) -> Node:
        n %= self.w
        if n == 0:
            return a
        if self.is_const(a):
            return self.c(rot_r(self.const_val(a), n, self.w))
        if a.key[0] == "rot":
            return self.rot(self._order[a.key[1]], a.key[2] + n)
        if a.key[0] == "xor":
            # rot distributes over xor
            x = self._order[a.key[1]]
            y = self._order[a.key[2]]
            return self.xor(self.rot(x, n), self.rot(y, n))
        return self._mk(("rot", a.nid, n))

    def shr(self, a: Node, n: int) -> Node:
        n = min(max(n, 0), self.w)
        if n == 0:
            return a
        if n == self.w:
            return self.c(0)
        if self.is_const(a):
            return self.c((self.const_val(a) >> n) & self.mask)
        return self._mk(("shr", a.nid, n))

    def eval(self, n: Node, env: Dict[str, int]) -> int:
        memo: Dict[int, int] = {}

        def go(x: Node) -> int:
            if x.nid in memo:
                return memo[x.nid]
            op = x.key[0]
            if op == "const":
                v = int(x.key[1])
            elif op == "var":
                v = env[x.key[1]] & self.mask
            elif op == "xor":
                v = go(self._order[x.key[1]]) ^ go(self._order[x.key[2]])
            elif op == "and":
                v = go(self._order[x.key[1]]) & go(self._order[x.key[2]])
            elif op == "not":
                v = (~go(self._order[x.key[1]])) & self.mask
            elif op == "add":
                v = (go(self._order[x.key[1]]) + go(self._order[x.key[2]])) & self.mask
            elif op == "rot":
                v = rot_r(go(self._order[x.key[1]]), int(x.key[2]), self.w)
            elif op == "shr":
                v = (go(self._order[x.key[1]]) >> int(x.key[2])) & self.mask
            else:
                raise ValueError(op)
            memo[x.nid] = v
            return v

        return go(n)

    def live_count(self, roots: Sequence[Node]) -> int:
        """Nodes reachable from roots (true circuit size after DCE)."""
        seen = set()
        stack = list(roots)
        while stack:
            n = stack.pop()
            if n.nid in seen:
                continue
            seen.add(n.nid)
            op = n.key[0]
            if op in ("xor", "and", "add"):
                stack.append(self._order[n.key[1]])
                stack.append(self._order[n.key[2]])
            elif op in ("not", "rot", "shr"):
                stack.append(self._order[n.key[1]])
        return len(seen)


def _sig0(d: Dag, x: Node) -> Node:
    return d.xor(d.xor(d.rot(x, 1), d.rot(x, 8 % d.w)), d.shr(x, 7))


def _sig1(d: Dag, x: Node) -> Node:
    return d.xor(d.xor(d.rot(x, 19 % d.w), d.rot(x, 61 % d.w)), d.shr(x, 6))


def _bs0(d: Dag, x: Node) -> Node:
    return d.xor(d.xor(d.rot(x, 28 % d.w), d.rot(x, 34 % d.w)), d.rot(x, 39 % d.w))


def _bs1(d: Dag, x: Node) -> Node:
    return d.xor(d.xor(d.rot(x, 14 % d.w), d.rot(x, 18 % d.w)), d.rot(x, 41 % d.w))


def _ch(d: Dag, e: Node, f: Node, g: Node) -> Node:
    return d.xor(d.and_(e, f), d.and_(d.not_(e), g))


def _maj(d: Dag, a: Node, b: Node, c: Node) -> Node:
    return d.xor(d.xor(d.and_(a, b), d.and_(a, c)), d.and_(b, c))


def symbolic_compress(
    d: Dag,
    iv: Sequence[Node],
    block: Sequence[Node],
    p: Params,
) -> List[Node]:
    reg: List[Node] = list(iv)
    while len(reg) < 8:
        reg.append(d.c(SHA512_H[len(reg)] & d.mask))
    sched: List[Node] = list(block)
    if p.use_schedule:
        while len(sched) < max(p.rounds, 16):
            sched.append(d.c(0))
        for i in range(16, p.rounds):
            sched[i] = d.add(
                d.add(sched[i - 16], _sig0(d, sched[i - 15])),
                d.add(sched[i - 7], _sig1(d, sched[i - 2])),
            )
    else:
        while len(sched) < p.rounds:
            sched.append(d.c(0))

    for i in range(p.rounds):
        a, b, c, e_a, e, f, g, h = (
            reg[0],
            reg[1],
            reg[2],
            reg[3],
            reg[4],
            reg[5],
            reg[6],
            reg[7],
        )
        s1 = _bs1(d, e)
        s0 = _bs0(d, a)
        if p.use_ch_maj:
            t_ch = _ch(d, e, f, g)
            t_maj = _maj(d, a, b, c)
        else:
            t_ch = d.xor(d.xor(e, f), g)
            t_maj = d.xor(d.xor(a, b), c)
        temp1 = d.add(d.add(d.add(d.add(h, s1), t_ch), d.c(k_word(i, p.w))), sched[i])
        temp2 = d.add(s0, t_maj)
        new_e = d.add(e_a, temp1)
        new_a = d.add(temp1, temp2)
        reg = [new_a, a, b, c, new_e, e, f, g] + reg[8:]

    out = []
    for j in range(p.words):
        ivj = iv[j] if j < len(iv) else d.c(0)
        out.append(d.add(ivj, reg[j]))
    return out


def symbolic_pad(d: Dag, x: Sequence[Node], p: Params) -> List[Node]:
    block_n = 16
    out = [d.c(0) for _ in range(block_n)]
    nmsg = min(p.words, 8, block_n)
    for i in range(nmsg):
        out[i] = x[i]
    pad_shift = max(p.w - 8, 0)
    if nmsg < block_n:
        out[nmsg] = d.c((0x80 << pad_shift) & d.mask)
    out[15] = d.c(HMAC64_BITLEN & d.mask)
    return out


def symbolic_F(
    p: Params, I: Sequence[int], O: Sequence[int]
) -> Tuple[Dag, List[Node], List[Node]]:
    d = Dag(p.w)
    x = [d.var(f"x{i}") for i in range(p.words)]
    i_nodes = [d.c(v) for v in I[: p.words]]
    o_nodes = [d.c(v) for v in O[: p.words]]
    while len(i_nodes) < p.words:
        i_nodes.append(d.c(0))
        o_nodes.append(d.c(0))
    mid = symbolic_compress(d, i_nodes, symbolic_pad(d, x, p), p)
    out = symbolic_compress(d, o_nodes, symbolic_pad(d, mid, p), p)
    return d, x, out


def compose_F(
    p: Params, I: Sequence[int], O: Sequence[int], times: int
) -> Tuple[Dag, List[Node], List[Node]]:
    """F^times as one DAG with rewrites, inputs still the original x."""
    d, x, out = symbolic_F(p, I, O)
    for _ in range(times - 1):
        out = symbolic_compress(d, [d.c(v) for v in I[: p.words]], symbolic_pad(d, out, p), p)
        out = symbolic_compress(d, [d.c(v) for v in O[: p.words]], symbolic_pad(d, out, p), p)
    return d, x, out


def xor_of_iterates_dag(
    p: Params, I: Sequence[int], O: Sequence[int], n: int
) -> Tuple[Dag, List[Node], List[Node]]:
    """DK = F(x) ⊕ ... ⊕ F^n(x) as a single rewritten DAG."""
    d, x, cur = symbolic_F(p, I, O)
    acc = list(cur)
    for _ in range(n - 1):
        cur = symbolic_compress(d, [d.c(v) for v in I[: p.words]], symbolic_pad(d, cur, p), p)
        cur = symbolic_compress(d, [d.c(v) for v in O[: p.words]], symbolic_pad(d, cur, p), p)
        acc = [d.xor(a, b) for a, b in zip(acc, cur)]
    return d, x, acc


def dag_report(
    p: Params, I: Sequence[int], O: Sequence[int], compose_n: int = 2, xor_n: int = 4
) -> dict:
    d1, _, y1 = symbolic_F(p, I, O)
    s1 = d1.live_count(y1)
    dc, _, yc = compose_F(p, I, O, compose_n)
    sc = dc.live_count(yc)
    dx, _, yx = xor_of_iterates_dag(p, I, O, xor_n)
    sx = dx.live_count(yx)
    return {
        "params": str(p),
        "F_live": s1,
        f"F^{compose_n}_live": sc,
        f"F^{compose_n}_over_F": round(sc / s1, 4) if s1 else None,
        f"xor_{xor_n}_live": sx,
        f"xor_{xor_n}_over_nF": round(sx / (s1 * xor_n), 4) if s1 else None,
        "rewrite": "const-fold, xor/add 0, x^x, rot∘rot, rot distributes over xor, not∘not, and 0/1",
    }
