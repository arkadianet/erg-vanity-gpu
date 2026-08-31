"""Bit-level DAG for a single mini-HMAC F, plus F² and G2.

Hash-consing is used only to get a tight *constructive upper bound*
from the definition of F (constant-folded I/O/pad). It is not the
synthesizer. SAT search lives in sat_mc.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from models import _SHA_K, _default_pad, _lcg, _randbits, _rots


@dataclass(frozen=True)
class Node:
    op: str
    a: int | None
    b: int | None
    const: int | None = None


@dataclass
class Counts:
    and_: int = 0
    xor: int = 0
    not_: int = 0
    add: int = 0
    rot: int = 0
    shr: int = 0
    const: int = 0

    @property
    def gates(self) -> int:
        return self.and_ + self.xor + self.not_

    @property
    def weighted_arx(self) -> int:
        # ADD is the expensive ARX primitive; ROT is a 2-bit wire perm.
        return 3 * self.add + 2 * self.and_ + self.xor + self.not_ + self.rot + self.shr

    def as_dict(self) -> dict:
        return {
            "and": self.and_,
            "xor": self.xor,
            "not": self.not_,
            "add": self.add,
            "rot": self.rot,
            "shr": self.shr,
            "gates": self.gates,
            "weighted_arx": self.weighted_arx,
        }


class Circuit:
    def __init__(self):
        self.nodes: list[Node] = []
        self._memo: dict[Node, int] = {}
        self.counts = Counts()
        self.inputs: list[int] = []

    def _mk(self, node: Node, bump: str | None) -> int:
        i = self._memo.get(node)
        if i is not None:
            return i
        i = len(self.nodes)
        self.nodes.append(node)
        self._memo[node] = i
        if bump:
            setattr(self.counts, bump, getattr(self.counts, bump) + 1)
        return i

    def input(self) -> int:
        i = len(self.nodes)
        self.nodes.append(Node("in", None, None, len(self.inputs)))
        self.inputs.append(i)
        return i

    def const(self, v: int) -> int:
        v &= 1
        return self._mk(Node("const", None, None, v), "const")

    def AND(self, a: int, b: int) -> int:
        if a > b:
            a, b = b, a
        na, nb = self.nodes[a], self.nodes[b]
        if na.op == "const":
            return b if na.const else self.const(0)
        if nb.op == "const":
            return a if nb.const else self.const(0)
        if a == b:
            return a
        return self._mk(Node("and", a, b), "and_")

    def XOR(self, a: int, b: int) -> int:
        if a > b:
            a, b = b, a
        na, nb = self.nodes[a], self.nodes[b]
        if na.op == "const" and nb.op == "const":
            return self.const(na.const ^ nb.const)
        if na.op == "const" and na.const == 0:
            return b
        if nb.op == "const" and nb.const == 0:
            return a
        if a == b:
            return self.const(0)
        return self._mk(Node("xor", a, b), "xor")

    def NOT(self, a: int) -> int:
        na = self.nodes[a]
        if na.op == "const":
            return self.const(1 - na.const)
        if na.op == "not":
            return na.a  # type: ignore[return-value]
        return self._mk(Node("not", a, None), "not_")

    def eval_bits(self, x: int, outs: list[int]) -> int:
        val = [0] * len(self.nodes)
        for i, n in enumerate(self.nodes):
            if n.op == "in":
                val[i] = (x >> n.const) & 1  # type: ignore[operator]
            elif n.op == "const":
                val[i] = n.const  # type: ignore[assignment]
            elif n.op == "and":
                val[i] = val[n.a] & val[n.b]  # type: ignore[index]
            elif n.op == "xor":
                val[i] = val[n.a] ^ val[n.b]  # type: ignore[index]
            elif n.op == "not":
                val[i] = 1 - val[n.a]  # type: ignore[index]
            else:
                raise ValueError(n.op)
        y = 0
        for j, o in enumerate(outs):
            y |= val[o] << j
        return y


class Word:
    def __init__(self, ckt: Circuit, bits: list[int]):
        self.c = ckt
        self.bits = bits

    @property
    def n(self) -> int:
        return len(self.bits)

    def xor(self, other: Word) -> Word:
        return Word(self.c, [self.c.XOR(a, b) for a, b in zip(self.bits, other.bits)])

    def and_(self, other: Word) -> Word:
        return Word(self.c, [self.c.AND(a, b) for a, b in zip(self.bits, other.bits)])

    def not_(self) -> Word:
        return Word(self.c, [self.c.NOT(b) for b in self.bits])

    def rotr(self, r: int) -> Word:
        r %= self.n
        if r == 0:
            return self
        self.c.counts.rot += 1
        return Word(self.c, self.bits[r:] + self.bits[:r])

    def shr(self, r: int) -> Word:
        r = min(r, self.n)
        self.c.counts.shr += 1
        z = self.c.const(0)
        # LSB-first: x >> r
        return Word(self.c, self.bits[r:] + [z] * r)

    def add(self, other: Word) -> Word:
        """Ripple-carry add, wrap at word width. Last carry is not materialized."""
        self.c.counts.add += 1
        s = []
        carry = self.c.const(0)
        last = self.n - 1
        for i, (a, b) in enumerate(zip(self.bits, other.bits)):
            axb = self.c.XOR(a, b)
            s.append(self.c.XOR(axb, carry))
            if i < last:
                carry = self.c.XOR(self.c.AND(a, b), self.c.AND(carry, axb))
        return Word(self.c, s)

    @staticmethod
    def const(ckt: Circuit, val: int, width: int) -> Word:
        return Word(ckt, [ckt.const((val >> i) & 1) for i in range(width)])


def _compress(ckt: Circuit, state: list[Word], msg: list[Word], bits: int, rounds: int, pad: list[int]) -> list[Word]:
    n = len(state)
    block_len = 2 * n
    W = list(msg) + [Word.const(ckt, pad[i], bits) for i in range(n)]
    s0r = _rots(bits, (1, 8, 7))
    s1r = _rots(bits, (19, 61, 6))
    while len(W) < rounds:
        i = len(W)
        w15 = W[i - (block_len - 1)]
        w2 = W[i - 2]
        w7 = W[i - (n - 1 if n > 1 else 1)]
        w16 = W[i - block_len]
        s0 = w15.rotr(s0r[0]).xor(w15.rotr(s0r[1])).xor(w15.shr(min(s0r[2], bits - 1)))
        s1 = w2.rotr(s1r[0]).xor(w2.rotr(s1r[1])).xor(w2.shr(min(s1r[2], bits - 1)))
        W.append(w16.add(s0).add(w7).add(s1))

    r14, r18, r41 = _rots(bits, (14, 18, 41))
    r28, r34, r39 = _rots(bits, (28, 34, 39))
    work = list(state)
    for i in range(rounds):
        if n == 8:
            a, b, c, d, e, f, g, h = work
        else:
            a, b, c, d = work
            e, f, g, h = b, c, d, a
        s1 = e.rotr(r14).xor(e.rotr(r18)).xor(e.rotr(r41))
        ch = e.and_(f).xor(e.not_().and_(g))
        k = Word.const(ckt, _SHA_K[i % len(_SHA_K)], bits)
        temp1 = h.add(s1).add(ch).add(k).add(W[i])
        s0 = a.rotr(r28).xor(a.rotr(r34)).xor(a.rotr(r39))
        maj = a.and_(b).xor(a.and_(c)).xor(b.and_(c))
        temp2 = s0.add(maj)
        if n == 8:
            work = [temp1.add(temp2), a, b, c, d.add(temp1), e, f, g]
        else:
            work = [temp1.add(temp2), a, b, c.add(temp1)]
    return [state[i].add(work[i]) for i in range(n)]


def build_hmac_family(nwords: int, bits: int, rounds: int, seed: int) -> dict:
    """One DAG containing x, F(x), F²(x), G2(x) with global hash-cons."""
    w = nwords * bits
    rng = _lcg(seed)
    I = [_randbits(rng, bits) for _ in range(nwords)]
    O = [_randbits(rng, bits) for _ in range(nwords)]
    pad = _default_pad(nwords, bits)

    ckt = Circuit()
    x_bits = [ckt.input() for _ in range(w)]
    x_words = [Word(ckt, x_bits[i * bits : (i + 1) * bits]) for i in range(nwords)]
    I_w = [Word.const(ckt, v, bits) for v in I]
    O_w = [Word.const(ckt, v, bits) for v in O]

    after_x = Counts(**{k: getattr(ckt.counts, k) for k in Counts().__dict__})

    inner = _compress(ckt, I_w, x_words, bits, rounds, pad)
    outer = _compress(ckt, O_w, inner, bits, rounds, pad)
    f_bits = [b for word in outer for b in word.bits]
    c_f = Counts(**{k: getattr(ckt.counts, k) for k in Counts().__dict__})

    inner2 = _compress(ckt, I_w, outer, bits, rounds, pad)
    outer2 = _compress(ckt, O_w, inner2, bits, rounds, pad)
    f2_bits = [b for word in outer2 for b in word.bits]
    c_f2 = Counts(**{k: getattr(ckt.counts, k) for k in Counts().__dict__})

    g2_bits = [ckt.XOR(a, b) for a, b in zip(f_bits, f2_bits)]
    c_g2 = Counts(**{k: getattr(ckt.counts, k) for k in Counts().__dict__})

    return {
        "circuit": ckt,
        "w": w,
        "I": I,
        "O": O,
        "f_bits": f_bits,
        "f2_bits": f2_bits,
        "g2_bits": g2_bits,
        "counts_F": c_f,
        "counts_F2_dag": c_f2,
        "counts_G2_dag": c_g2,
        "counts_empty": after_x,
    }


def cone_and_count(ckt: Circuit, out: int) -> int:
    """AND gates that reach `out` (exact DCE upper bound for one bit)."""
    need = {out}
    for i in range(out, -1, -1):
        if i not in need:
            continue
        n = ckt.nodes[i]
        if n.a is not None:
            need.add(n.a)
        if n.b is not None:
            need.add(n.b)
    return sum(1 for i in need if ckt.nodes[i].op == "and")


def cone_gate_count(ckt: Circuit, out: int) -> dict:
    need = {out}
    for i in range(out, -1, -1):
        if i not in need:
            continue
        n = ckt.nodes[i]
        if n.a is not None:
            need.add(n.a)
        if n.b is not None:
            need.add(n.b)
    c = {"and": 0, "xor": 0, "not": 0}
    for i in need:
        op = ckt.nodes[i].op
        if op in c:
            c[op] += 1
    c["gates"] = c["and"] + c["xor"] + c["not"]
    return c


def two_copy_upper_bound(counts_F: Counts) -> Counts:
    """Naive G2 = F ⊕ F∘F with no cross-iteration sharing except F's outputs."""
    c = Counts(
        and_=2 * counts_F.and_,
        xor=2 * counts_F.xor + counts_F.and_ * 0,
        not_=2 * counts_F.not_,
        add=2 * counts_F.add,
        rot=2 * counts_F.rot,
        shr=2 * counts_F.shr,
    )
    #  w XOR for the outer G2 — added below by caller if needed
    return c
