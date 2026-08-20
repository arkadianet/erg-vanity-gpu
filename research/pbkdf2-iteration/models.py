"""Reduced-width models of PBKDF2's iterated F.

F after HMAC midstate precomputation is

    F(x) = Compress(O, pad(Compress(I, pad(x))))

These models increase SHA-likeness without touching the production
PBKDF2 implementation. Every model is a map on w-bit strings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Cost:
    add: int = 0
    xor: int = 0
    and_: int = 0
    not_: int = 0
    rot: int = 0
    shr: int = 0

    @property
    def total(self) -> int:
        return self.add + self.xor + self.and_ + self.not_ + self.rot + self.shr

    def add_cost(self, other: Cost) -> None:
        self.add += other.add
        self.xor += other.xor
        self.and_ += other.and_
        self.not_ += other.not_
        self.rot += other.rot
        self.shr += other.shr


class Ops:
    """Word operations with optional cost accounting."""

    def __init__(self, bits: int, cost: Cost | None = None):
        self.bits = bits
        self.mask = (1 << bits) - 1
        self.cost = cost

    def _bump(self, attr: str, n: int = 1) -> None:
        if self.cost is not None:
            setattr(self.cost, attr, getattr(self.cost, attr) + n)

    def add(self, a: int, b: int) -> int:
        self._bump("add")
        return (a + b) & self.mask

    def xor(self, a: int, b: int) -> int:
        self._bump("xor")
        return (a ^ b) & self.mask

    def and_(self, a: int, b: int) -> int:
        self._bump("and_")
        return (a & b) & self.mask

    def not_(self, a: int) -> int:
        self._bump("not_")
        return (~a) & self.mask

    def rotr(self, a: int, n: int) -> int:
        self._bump("rot")
        n %= self.bits
        if n == 0:
            return a & self.mask
        return ((a >> n) | (a << (self.bits - n))) & self.mask

    def shr(self, a: int, n: int) -> int:
        self._bump("shr")
        return (a >> n) & self.mask


def pack_words(words: list[int], bits: int) -> int:
    x = 0
    for i, w in enumerate(words):
        x |= (w & ((1 << bits) - 1)) << (i * bits)
    return x


def unpack_words(x: int, nwords: int, bits: int) -> list[int]:
    mask = (1 << bits) - 1
    return [(x >> (i * bits)) & mask for i in range(nwords)]


@dataclass
class Model:
    name: str
    w: int
    eval: Callable[[int, Cost | None], int]
    note: str = ""

    def f(self, x: int, cost: Cost | None = None) -> int:
        return self.eval(x & ((1 << self.w) - 1), cost) & ((1 << self.w) - 1)

    def cost_of_f(self, x: int = 1) -> Cost:
        c = Cost()
        self.f(x, c)
        return c


def linear_map(w: int, seed: int = 1) -> Model:
    """F(x) = A x ⊕ b over GF(2). Closed-form G_n exists."""
    rng = _lcg(seed)
    A = [_randbits(rng, w) for _ in range(w)]
    # force A invertible-ish by making it upper-triangular with 1s on diagonal
    for i in range(w):
        A[i] |= 1 << i
        A[i] &= ~((1 << i) - 1)
        A[i] |= _randbits(rng, w) & ~((1 << (i + 1)) - 1)
        A[i] |= 1 << i
    b = _randbits(rng, w)

    def apply_A(x: int) -> int:
        y = 0
        for i in range(w):
            if (x >> i) & 1:
                y ^= A[i]
        return y

    def ev(x: int, cost: Cost | None) -> int:
        ops = Ops(w, cost)
        y = 0
        for i in range(w):
            if (x >> i) & 1:
                y = ops.xor(y, A[i])
        return ops.xor(y, b)

    return Model(
        name=f"linear_w{w}",
        w=w,
        eval=ev,
        note="affine over GF(2); geometric series is O(w^3 log n)",
    )


def quadratic_map(w: int, seed: int = 2) -> Model:
    """Sparse quadratic perturbation of an affine map."""
    rng = _lcg(seed)
    A = [_randbits(rng, w) for _ in range(w)]
    for i in range(w):
        A[i] |= 1 << i
    b = _randbits(rng, w)
    # a few AND terms: bit i of output ^= x_j & x_k
    quads = []
    for _ in range(max(2, w // 2)):
        i = _randbits(rng, 8) % w
        j = _randbits(rng, 8) % w
        k = _randbits(rng, 8) % w
        if j != k:
            quads.append((i, j, k))

    def ev(x: int, cost: Cost | None) -> int:
        ops = Ops(w, cost)
        y = 0
        for i in range(w):
            if (x >> i) & 1:
                y = ops.xor(y, A[i])
        y = ops.xor(y, b)
        for i, j, k in quads:
            term = ops.and_((x >> j) & 1, (x >> k) & 1)
            y = ops.xor(y, term << i)
        return y

    return Model(
        name=f"quadratic_w{w}",
        w=w,
        eval=ev,
        note="affine + sparse ANDs",
    )


def tiny_nlr(w: int, seed: int = 3) -> Model:
    """Tiny nonlinear recurrence: x -> (x + (x<<1) + 1) xor rotr(x,1), masked."""
    c = (seed * 0x9E3779B1) & ((1 << w) - 1)

    def ev(x: int, cost: Cost | None) -> int:
        ops = Ops(w, cost)
        y = ops.add(x, ops.add((x << 1) & ops.mask, 1))
        return ops.xor(y, ops.rotr(x, 1) ^ c)

    return Model(name=f"tiny_nlr_w{w}", w=w, eval=ev, note="add/shift/xor recurrence")


def arx_map(nwords: int, bits: int, rounds: int, seed: int = 4) -> Model:
    """Pure ARX: add-rotate-xor on nwords of `bits` bits."""
    w = nwords * bits
    rng = _lcg(seed)
    ks = [_randbits(rng, bits) for _ in range(rounds * nwords)]
    r1 = 1 if bits == 1 else (bits // 3 or 1)
    r2 = 1 if bits == 1 else (2 * bits // 3 or 1)

    def ev(x: int, cost: Cost | None) -> int:
        ops = Ops(bits, cost)
        s = unpack_words(x, nwords, bits)
        ki = 0
        for _ in range(rounds):
            for i in range(nwords):
                j = (i + 1) % nwords
                s[i] = ops.add(s[i], s[j])
                s[i] = ops.xor(s[i], ops.rotr(s[j], r1))
                s[i] = ops.add(s[i], ks[ki])
                s[j] = ops.xor(s[j], ops.rotr(s[i], r2))
                ki += 1
        return pack_words(s, bits)

    return Model(
        name=f"arx_n{nwords}b{bits}r{rounds}",
        w=w,
        eval=ev,
        note="ARX only",
    )


def _arx_forward(s: list[int], ks: list[int], bits: int, r1: int, r2: int, cost: Cost | None) -> list[int]:
    ops = Ops(bits, cost)
    nwords = len(s)
    ki = 0
    for _ in range(len(ks) // nwords):
        for i in range(nwords):
            j = (i + 1) % nwords
            s[i] = ops.add(s[i], s[j])
            s[i] = ops.xor(s[i], ops.rotr(s[j], r1))
            s[i] = ops.add(s[i], ks[ki])
            s[j] = ops.xor(s[j], ops.rotr(s[i], r2))
            ki += 1
    return s


def _arx_inverse(s: list[int], ks: list[int], bits: int, r1: int, r2: int, cost: Cost | None) -> list[int]:
    ops = Ops(bits, cost)
    nwords = len(s)
    rounds = len(ks) // nwords
    for r in range(rounds - 1, -1, -1):
        for i in range(nwords - 1, -1, -1):
            j = (i + 1) % nwords
            ki = r * nwords + i
            s[j] = ops.xor(s[j], ops.rotr(s[i], r2))
            s[i] = (s[i] - ks[ki]) & ops.mask
            if cost is not None:
                cost.add += 1
            s[i] = ops.xor(s[i], ops.rotr(s[j], r1))
            s[i] = (s[i] - s[j]) & ops.mask
            if cost is not None:
                cost.add += 1
    return s


def arx_hmac(nwords: int, bits: int, rounds: int, seed: int = 21) -> dict:
    """Two-key invertible ARX stand-in for HMAC: F = ARX_O ∘ ARX_I.

    Unlike reduced SHA+Ch/Maj, each half is a permutation, as HMAC-SHA512
    of a single 64-byte block is (SHACAL-2 is a permutation in the message).
    """
    w = nwords * bits
    rng = _lcg(seed)
    ks_i = [_randbits(rng, bits) for _ in range(rounds * nwords)]
    ks_o = [_randbits(rng, bits) for _ in range(rounds * nwords)]
    r1 = 1 if bits == 1 else (bits // 3 or 1)
    r2 = 1 if bits == 1 else (2 * bits // 3 or 1)

    def H_I(x: int, cost: Cost | None = None) -> int:
        s = unpack_words(x, nwords, bits)
        return pack_words(_arx_forward(s, ks_i, bits, r1, r2, cost), bits)

    def H_O(x: int, cost: Cost | None = None) -> int:
        s = unpack_words(x, nwords, bits)
        return pack_words(_arx_forward(s, ks_o, bits, r1, r2, cost), bits)

    def F(x: int, cost: Cost | None = None) -> int:
        return H_O(H_I(x, cost), cost)

    def F_inv(x: int, cost: Cost | None = None) -> int:
        s = unpack_words(x, nwords, bits)
        s = _arx_inverse(s, ks_o, bits, r1, r2, cost)
        s = _arx_inverse(s, ks_i, bits, r1, r2, cost)
        return pack_words(s, bits)

    return {
        "w": w,
        "H_I": Model(f"arxHI_n{nwords}b{bits}r{rounds}", w, lambda x, c: H_I(x, c)),
        "H_O": Model(f"arxHO_n{nwords}b{bits}r{rounds}", w, lambda x, c: H_O(x, c)),
        "F": Model(f"arxhmac_n{nwords}b{bits}r{rounds}", w, lambda x, c: F(x, c)),
        "F_inv": Model(f"arxhmacInv_n{nwords}b{bits}r{rounds}", w, lambda x, c: F_inv(x, c)),
    }


def arx_chmaj_map(nwords: int, bits: int, rounds: int, seed: int = 5) -> Model:
    """ARX plus Ch/Maj, still a single map (not two-compress HMAC)."""
    w = nwords * bits
    if nwords < 4:
        raise ValueError("Ch/Maj model needs at least 4 words")
    rng = _lcg(seed)
    ks = [_randbits(rng, bits) for _ in range(rounds)]
    r14, r18, r41 = _rots(bits, (14, 18, 41))
    r28, r34, r39 = _rots(bits, (28, 34, 39))

    def ev(x: int, cost: Cost | None) -> int:
        ops = Ops(bits, cost)
        s = unpack_words(x, nwords, bits)
        # use last 4 words as a,e,f,g-like if nwords>=8 we use SHA layout
        for r in range(rounds):
            a, e = s[0], s[nwords // 2]
            f = s[(nwords // 2 + 1) % nwords]
            g = s[(nwords // 2 + 2) % nwords]
            b = s[1 % nwords]
            c = s[2 % nwords]
            s1 = ops.xor(ops.xor(ops.rotr(e, r14), ops.rotr(e, r18)), ops.rotr(e, r41))
            ch = ops.xor(ops.and_(e, f), ops.and_(ops.not_(e), g))
            t1 = ops.add(ops.add(s1, ch), ks[r])
            s0 = ops.xor(ops.xor(ops.rotr(a, r28), ops.rotr(a, r34)), ops.rotr(a, r39))
            maj = ops.xor(ops.xor(ops.and_(a, b), ops.and_(a, c)), ops.and_(b, c))
            t2 = ops.add(s0, maj)
            # rotate state like SHA
            ns = s[:]
            for i in range(nwords - 1, 0, -1):
                ns[i] = s[i - 1]
            ns[nwords // 2] = ops.add(s[nwords // 2 - 1] if nwords >= 2 else s[0], t1)
            ns[0] = ops.add(t1, t2)
            s = ns
        return pack_words(s, bits)

    return Model(
        name=f"arxch_n{nwords}b{bits}r{rounds}",
        w=w,
        eval=ev,
        note="ARX + Ch + Maj",
    )


# Low bits of real SHA-512 K, used as reduced-width constants.
_SHA_K = [
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
]


def _rots(bits: int, rs: tuple[int, ...]) -> tuple[int, ...]:
    return tuple((r % bits) or 1 for r in rs)


def mini_compress(
    state: list[int],
    msg: list[int],
    bits: int,
    rounds: int,
    ops: Ops,
    pad: list[int] | None = None,
) -> list[int]:
    """Reduced SHA compression: Davies-Meyer, fixed pad words, SHA-like schedule."""
    n = len(state)
    if n not in (4, 8):
        raise ValueError(f"unsupported word count {n}")
    pad = pad if pad is not None else _default_pad(n, bits)
    block_len = 2 * n
    W = [msg[i] & ops.mask for i in range(n)] + [pad[i] & ops.mask for i in range(n)]
    s0r = _rots(bits, (1, 8, 7))
    s1r = _rots(bits, (19, 61, 6))
    while len(W) < rounds:
        i = len(W)
        w15 = W[i - (block_len - 1)]
        w2 = W[i - 2]
        w7 = W[i - (n - 1 if n > 1 else 1)]
        w16 = W[i - block_len]
        s0 = ops.xor(
            ops.xor(ops.rotr(w15, s0r[0]), ops.rotr(w15, s0r[1])),
            ops.shr(w15, min(s0r[2], bits - 1)),
        )
        s1 = ops.xor(
            ops.xor(ops.rotr(w2, s1r[0]), ops.rotr(w2, s1r[1])),
            ops.shr(w2, min(s1r[2], bits - 1)),
        )
        W.append(ops.add(ops.add(ops.add(w16, s0), w7), s1))

    r14, r18, r41 = _rots(bits, (14, 18, 41))
    r28, r34, r39 = _rots(bits, (28, 34, 39))
    work = list(state)
    for i in range(rounds):
        if n == 8:
            a, b, c, d, e, f, g, h = work
        else:
            a, b, c, d = work
            e, f, g, h = b, c, d, a
        s1 = ops.xor(ops.xor(ops.rotr(e, r14), ops.rotr(e, r18)), ops.rotr(e, r41))
        ch = ops.xor(ops.and_(e, f), ops.and_(ops.not_(e), g))
        k = _SHA_K[i % len(_SHA_K)] & ops.mask
        temp1 = ops.add(ops.add(ops.add(ops.add(h, s1), ch), k), W[i])
        s0 = ops.xor(ops.xor(ops.rotr(a, r28), ops.rotr(a, r34)), ops.rotr(a, r39))
        maj = ops.xor(ops.xor(ops.and_(a, b), ops.and_(a, c)), ops.and_(b, c))
        temp2 = ops.add(s0, maj)
        if n == 8:
            work = [ops.add(temp1, temp2), a, b, c, ops.add(d, temp1), e, f, g]
        else:
            work = [ops.add(temp1, temp2), a, b, ops.add(c, temp1)]

    return [ops.add(state[i], work[i]) for i in range(n)]


def _default_pad(n: int, bits: int) -> list[int]:
    """HMAC-like second-half block: 1-bit, zeros, bit-length of (IV-block + message)."""
    pad = [0] * n
    pad[0] = 1 << (bits - 1)
    pad[-1] = ((2 * n) * bits) & ((1 << bits) - 1)
    return pad


def mini_sha(nwords: int, bits: int, rounds: int, seed: int = 6) -> Model:
    rng = _lcg(seed)
    iv = [_randbits(rng, bits) for _ in range(nwords)]
    pad = _default_pad(nwords, bits)
    w = nwords * bits

    def ev(x: int, cost: Cost | None) -> int:
        ops = Ops(bits, cost)
        msg = unpack_words(x, nwords, bits)
        out = mini_compress(iv, msg, bits, rounds, ops, pad)
        return pack_words(out, bits)

    return Model(
        name=f"minisha_n{nwords}b{bits}r{rounds}",
        w=w,
        eval=ev,
        note="reduced SHA-512 compression, fixed IV, HMAC-like padding",
    )


def mini_hmac_parts(nwords: int, bits: int, rounds: int, seed: int = 7) -> dict:
    """Inner/outer compressions of mini-HMAC, as separate maps."""
    rng = _lcg(seed)
    I = [_randbits(rng, bits) for _ in range(nwords)]
    O = [_randbits(rng, bits) for _ in range(nwords)]
    pad = _default_pad(nwords, bits)
    w = nwords * bits

    def H_I(x: int, cost: Cost | None = None) -> int:
        ops = Ops(bits, cost)
        inner = mini_compress(I, unpack_words(x, nwords, bits), bits, rounds, ops, pad)
        return pack_words(inner, bits)

    def H_O(x: int, cost: Cost | None = None) -> int:
        ops = Ops(bits, cost)
        outer = mini_compress(O, unpack_words(x, nwords, bits), bits, rounds, ops, pad)
        return pack_words(outer, bits)

    def F(x: int, cost: Cost | None = None) -> int:
        return H_O(H_I(x, cost), cost)

    return {
        "w": w,
        "H_I": Model(f"HI_n{nwords}b{bits}r{rounds}", w, lambda x, c: H_I(x, c)),
        "H_O": Model(f"HO_n{nwords}b{bits}r{rounds}", w, lambda x, c: H_O(x, c)),
        "F": Model(f"minihmac_n{nwords}b{bits}r{rounds}", w, lambda x, c: F(x, c)),
        "I": I,
        "O": O,
    }


def mini_hmac(nwords: int, bits: int, rounds: int, seed: int = 7) -> Model:
    """Two-compress HMAC-like F with fixed I/O midstates and fixed padding."""
    rng = _lcg(seed)
    I = [_randbits(rng, bits) for _ in range(nwords)]
    O = [_randbits(rng, bits) for _ in range(nwords)]
    pad = _default_pad(nwords, bits)
    w = nwords * bits

    def ev(x: int, cost: Cost | None) -> int:
        ops = Ops(bits, cost)
        msg = unpack_words(x, nwords, bits)
        inner = mini_compress(I, msg, bits, rounds, ops, pad)
        outer = mini_compress(O, inner, bits, rounds, ops, pad)
        return pack_words(outer, bits)

    return Model(
        name=f"minihmac_n{nwords}b{bits}r{rounds}",
        w=w,
        eval=ev,
        note="F(x)=Compress(O,pad(Compress(I,pad(x))))",
    )


def iterate(model: Model, x: int, n: int, cost: Cost | None = None) -> int:
    for _ in range(n):
        x = model.f(x, cost)
    return x


def xor_iterates(model: Model, x: int, n: int, cost: Cost | None = None) -> int:
    acc = 0
    u = x
    for _ in range(n):
        u = model.f(u, cost)
        acc ^= u
    return acc


def _lcg(seed: int):
    x = seed & 0xFFFFFFFF

    def nxt() -> int:
        nonlocal x
        x = (x * 1664525 + 1013904223) & 0xFFFFFFFF
        return x

    return nxt


def _randbits(rng, bits: int) -> int:
    if bits <= 32:
        return rng() & ((1 << bits) - 1)
    v = 0
    got = 0
    while got < bits:
        v |= (rng() << got)
        got += 32
    return v & ((1 << bits) - 1)
