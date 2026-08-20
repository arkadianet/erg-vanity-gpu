"""Parameterized models of the BIP39 PBKDF2-HMAC-SHA512 iteration map.

The object of study is not a generic hash. After HMAC ipad/opad precomputation
the iteration is always

    F(x) = Compress(O, pad64(Compress(I, pad64(x))))

with |x| = 512 bits and pad64 the unique SHA-512 padding of a 64-byte message.
PBKDF2 then returns the orbit XOR

    DK = F(x) XOR F^2(x) XOR ... XOR F^n(x)

Models climb the ladder: toy -> ARX -> ARX+Ch/Maj -> reduced SHA -> reduced HMAC
-> full HMAC-SHA512 (sample tests only).
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Callable, Iterable, List, Sequence, Tuple

# SHA-512 IV and K (FIPS 180-4). Used by the full-width reference and by
# reduced models (K is truncated / masked to the word width).
SHA512_H = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
]

SHA512_K = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
]

# HMAC 64-byte message after a 128-byte ipad/opad block: 192 bytes = 1536 bits.
HMAC64_BITLEN = 1536


def mask_of(w: int) -> int:
    return (1 << w) - 1


def rot_r(x: int, n: int, w: int) -> int:
    n %= w
    m = mask_of(w)
    x &= m
    return ((x >> n) | (x << (w - n))) & m


def shr(x: int, n: int, w: int) -> int:
    return (x & mask_of(w)) >> min(n, w)


@dataclass(frozen=True)
class Params:
    """One rung of the model ladder.

    words=8, sched=16 matches SHA-512's 8-word state and 16-word block.
    w and rounds shrink independently so a toy win can be re-tested at
    larger width before anyone talks about SHA-512.
    """

    w: int
    words: int = 8
    rounds: int = 8
    use_ch_maj: bool = True
    use_schedule: bool = True
    name: str = ""

    @property
    def mask(self) -> int:
        return mask_of(self.w)

    @property
    def state_bits(self) -> int:
        return self.w * self.words

    @property
    def sched_len(self) -> int:
        # SHA-512 expands 16 block words to `rounds` schedule words.
        return max(self.rounds, 16) if self.use_schedule else self.rounds

    def __str__(self) -> str:
        tag = self.name or (
            f"w{self.w}_n{self.words}_r{self.rounds}"
            f"{'_ch' if self.use_ch_maj else '_arx'}"
            f"{'' if self.use_schedule else '_nosched'}"
        )
        return tag


# Ladder used by the experiment runner. Names are the discipline in the brief.
LADDER: List[Params] = [
    Params(w=8, words=1, rounds=2, use_ch_maj=False, use_schedule=False, name="toy8"),
    Params(w=12, words=1, rounds=3, use_ch_maj=False, use_schedule=False, name="toy12"),
    Params(w=4, words=4, rounds=4, use_ch_maj=False, use_schedule=True, name="arx4x4r4"),
    Params(w=4, words=8, rounds=4, use_ch_maj=False, use_schedule=True, name="arx4x8r4"),
    Params(w=8, words=4, rounds=4, use_ch_maj=False, use_schedule=True, name="arx8x4r4"),
    Params(w=4, words=8, rounds=4, use_ch_maj=True, use_schedule=True, name="ch4x8r4"),
    Params(w=8, words=4, rounds=8, use_ch_maj=True, use_schedule=True, name="ch8x4r8"),
    Params(w=8, words=8, rounds=8, use_ch_maj=True, use_schedule=True, name="sha8x8r8"),
    Params(w=16, words=8, rounds=16, use_ch_maj=True, use_schedule=True, name="sha16x8r16"),
    Params(w=64, words=8, rounds=20, use_ch_maj=True, use_schedule=True, name="sha64r20"),
    Params(w=64, words=8, rounds=80, use_ch_maj=True, use_schedule=True, name="sha512"),
]


def sigma0(x: int, w: int) -> int:
    return rot_r(x, 1, w) ^ rot_r(x, 8 % w, w) ^ shr(x, 7, w)


def sigma1(x: int, w: int) -> int:
    return rot_r(x, 19 % w, w) ^ rot_r(x, 61 % w, w) ^ shr(x, 6, w)


def big_sigma0(x: int, w: int) -> int:
    return rot_r(x, 28 % w, w) ^ rot_r(x, 34 % w, w) ^ rot_r(x, 39 % w, w)


def big_sigma1(x: int, w: int) -> int:
    return rot_r(x, 14 % w, w) ^ rot_r(x, 18 % w, w) ^ rot_r(x, 41 % w, w)


def ch(e: int, f: int, g: int, w: int) -> int:
    m = mask_of(w)
    return ((e & f) ^ ((~e) & g)) & m


def maj(a: int, b: int, c: int, w: int) -> int:
    return ((a & b) ^ (a & c) ^ (b & c)) & mask_of(w)


def k_word(i: int, w: int) -> int:
    return SHA512_K[i % 80] & mask_of(w)


def iv_words(p: Params) -> List[int]:
    m = p.mask
    return [SHA512_H[i % 8] & m for i in range(p.words)]


def pad64_words(x: Sequence[int], p: Params) -> List[int]:
    """SHA-512-style padding of a one-block-half message (the 64-byte HMAC case).

    Layout matches the real envelope: 8 message words, 0x80, zeros, bit length
    of (128 + 64) bytes. Extra state words beyond 8 are taken from x so the
    model stays well-defined when words != 8.
    """
    m = p.mask
    block = 16 if p.use_schedule or p.words >= 8 else max(16, p.words + 8)
    wds = [int(v) & m for v in x]
    if len(wds) < p.words:
        wds.extend([0] * (p.words - len(wds)))
    out = [0] * block
    nmsg = min(p.words, 8, block)
    for i in range(nmsg):
        out[i] = wds[i]
    if block > nmsg:
        # 0x80 in the first padding byte of a w-bit word (SHA-512: 0x80 << 56).
        pad_shift = max(p.w - 8, 0)
        out[nmsg] = (0x80 << pad_shift) & m
    if block >= 16:
        out[15] = HMAC64_BITLEN & m
    elif block > 0:
        out[-1] = HMAC64_BITLEN & m
    return out


def expand_schedule(block: Sequence[int], p: Params) -> List[int]:
    m = p.mask
    n = max(p.rounds, len(block))
    wsch = [int(v) & m for v in block]
    if len(wsch) < n:
        wsch.extend([0] * (n - len(wsch)))
    if not p.use_schedule:
        return wsch[: p.rounds]
    for i in range(16, p.rounds):
        s0 = sigma0(wsch[i - 15], p.w)
        s1 = sigma1(wsch[i - 2], p.w)
        wsch[i] = (wsch[i - 16] + s0 + wsch[i - 7] + s1) & m
    return wsch[: p.rounds]


@dataclass
class RoundTrace:
    """Per-round working state, for related-message / cone experiments."""

    states: List[Tuple[int, ...]]  # after each round, length = rounds
    schedule: List[int]
    iv: Tuple[int, ...]
    out: Tuple[int, ...]


def compress(
    iv: Sequence[int],
    block: Sequence[int],
    p: Params,
    trace: bool = False,
) -> Tuple[List[int], RoundTrace | None]:
    """Davies-Meyer compression with SHA-512's round skeleton."""
    m = p.mask
    words = list(iv)
    if len(words) < p.words:
        words.extend(iv_words(p)[len(words) : p.words])
    words = [w & m for w in words[: p.words]]
    # Working registers: SHA uses 8. Extra model words sit in the tail and
    # rotate through the same Feistel update so width scaling is uniform.
    reg = words[:]
    while len(reg) < 8:
        reg.append(SHA512_H[len(reg)] & m)
    sched = expand_schedule(block, p)
    states: List[Tuple[int, ...]] = []

    for i in range(p.rounds):
        a, b, c, d, e, f, g, h = reg[:8]
        s1 = big_sigma1(e, p.w)
        s0 = big_sigma0(a, p.w)
        if p.use_ch_maj:
            t_ch = ch(e, f, g, p.w)
            t_maj = maj(a, b, c, p.w)
        else:
            t_ch = (e ^ f ^ g) & m
            t_maj = (a ^ b ^ c) & m
        temp1 = (h + s1 + t_ch + k_word(i, p.w) + sched[i]) & m
        temp2 = (s0 + t_maj) & m
        new_e = (d + temp1) & m
        new_a = (temp1 + temp2) & m
        # Tail words (when words>8) shift along; when words<8 they are unused.
        tail = reg[8:]
        reg = [new_a, a, b, c, new_e, e, f, g] + tail
        if tail:
            # keep a cheap mixing of extra words so they are not dead state
            reg[8] = (tail[0] + new_a) & m
        if trace:
            states.append(tuple(reg[: p.words]))

    out = [(words[j] + reg[j]) & m for j in range(p.words)]
    tr = None
    if trace:
        tr = RoundTrace(
            states=states,
            schedule=list(sched),
            iv=tuple(words),
            out=tuple(out),
        )
    return out, tr


def pack_state(words: Sequence[int], p: Params) -> int:
    x = 0
    for i, v in enumerate(words[: p.words]):
        x |= (int(v) & p.mask) << (i * p.w)
    return x


def unpack_state(x: int, p: Params) -> List[int]:
    m = p.mask
    return [(x >> (i * p.w)) & m for i in range(p.words)]


def sha_map(x: int, iv: Sequence[int], p: Params) -> int:
    """One padded compression: the inner (or outer) half of F."""
    words = unpack_state(x, p)
    block = pad64_words(words, p)
    out, _ = compress(iv, block, p)
    return pack_state(out, p)


def hmac_F(x: int, inner_iv: Sequence[int], outer_iv: Sequence[int], p: Params) -> int:
    mid = sha_map(x, inner_iv, p)
    return sha_map(mid, outer_iv, p)


def orbit_xor(x: int, fn: Callable[[int], int], n: int) -> Tuple[int, int]:
    """Return (F^n(x), F(x) XOR ... XOR F^n(x))."""
    acc = 0
    u = x
    last = x
    for _ in range(n):
        u = fn(u)
        acc ^= u
        last = u
    return last, acc


def make_fixed_ivs(p: Params, seed: int = 0xC0FFEE) -> Tuple[List[int], List[int]]:
    """Deterministic I, O standing in for Compress(H0, K⊕ipad/opad)."""
    m = p.mask
    i_iv = [((SHA512_H[j % 8] ^ (seed * (j + 1))) + 0x36 * (j + 3)) & m for j in range(p.words)]
    o_iv = [((SHA512_H[j % 8] ^ (seed * (j + 5))) + 0x5C * (j + 7)) & m for j in range(p.words)]
    return i_iv, o_iv


class Envelope:
    """Fixed-I/O HMAC envelope on a Params rung."""

    def __init__(self, p: Params, seed: int = 0xC0FFEE):
        self.p = p
        self.I, self.O = make_fixed_ivs(p, seed)
        self._cost_one = None

    def F(self, x: int) -> int:
        return hmac_F(x, self.I, self.O, self.p)

    def sha_inner(self, x: int) -> int:
        return sha_map(x, self.I, self.p)

    def sha_outer(self, x: int) -> int:
        return sha_map(x, self.O, self.p)

    def dk(self, x: int, n: int) -> int:
        return orbit_xor(x, self.F, n)[1]

    def iterates(self, x: int, n: int) -> List[int]:
        out = []
        u = x
        for _ in range(n):
            u = self.F(u)
            out.append(u)
        return out


# ---------------------------------------------------------------------------
# Full HMAC-SHA512 (64-byte message path) via hashlib, plus an instrumented
# compression for related-message tests.
# ---------------------------------------------------------------------------

def _bytes_to_words(b: bytes) -> List[int]:
    return list(struct.unpack(">8Q", b))


def _words_to_bytes(w: Sequence[int]) -> bytes:
    return struct.pack(">8Q", *[int(x) & ((1 << 64) - 1) for x in w])


def hmac_sha512_64(key: bytes, msg64: bytes) -> bytes:
    if len(msg64) != 64:
        raise ValueError("msg64 must be 64 bytes")
    return hmac.new(key, msg64, hashlib.sha512).digest()


def pbkdf2_hmac_sha512_block1(password: bytes, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", password, salt, iterations, dklen=64)


def instrumented_sha512_compress(iv: Sequence[int], block64: Sequence[int]) -> RoundTrace:
    """Full 80-round SHA-512 compression with a 16-word block."""
    p = Params(w=64, words=8, rounds=80, use_ch_maj=True, use_schedule=True, name="sha512")
    block = list(block64)
    if len(block) != 16:
        raise ValueError("SHA-512 block is 16 words")
    out, tr = compress(iv, block, p, trace=True)
    assert tr is not None
    return tr


def hmac64_pad_block(msg_words: Sequence[int]) -> List[int]:
    """Exact 16-word block for a 64-byte message after a 128-byte prefix."""
    w = [int(x) & ((1 << 64) - 1) for x in msg_words]
    if len(w) != 8:
        raise ValueError("need 8 words")
    return w + [0x8000000000000000, 0, 0, 0, 0, 0, 0, HMAC64_BITLEN]


def hmac_midstates(key: bytes) -> Tuple[List[int], List[int]]:
    """I, O = Compress(H0, K'⊕ipad), Compress(H0, K'⊕opad)."""
    if len(key) > 128:
        key = hashlib.sha512(key).digest()
    keyb = key.ljust(128, b"\x00")
    ipad = bytes(b ^ 0x36 for b in keyb)
    opad = bytes(b ^ 0x5C for b in keyb)
    # One-block compress from IV. Use our compress so I/O match the model.
    p = Params(w=64, words=8, rounds=80, use_ch_maj=True, use_schedule=True, name="sha512")
    i_block = list(struct.unpack(">16Q", ipad))
    o_block = list(struct.unpack(">16Q", opad))
    I, _ = compress(SHA512_H, i_block, p)
    O, _ = compress(SHA512_H, o_block, p)
    return I, O


def hmac64_F_words(I: Sequence[int], O: Sequence[int], x: Sequence[int]) -> List[int]:
    p = Params(w=64, words=8, rounds=80, use_ch_maj=True, use_schedule=True, name="sha512")
    inner, _ = compress(I, hmac64_pad_block(x), p)
    outer, _ = compress(O, hmac64_pad_block(inner), p)
    return outer


def verify_full_hmac_against_stdlib(trials: int = 8) -> None:
    """Independent check that the instrumented envelope matches hashlib."""
    import os

    for _ in range(trials):
        key = os.urandom(32)
        msg = os.urandom(64)
        I, O = hmac_midstates(key)
        got = _words_to_bytes(hmac64_F_words(I, O, _bytes_to_words(msg)))
        ref = hmac_sha512_64(key, msg)
        if got != ref:
            raise AssertionError("instrumented HMAC-SHA512 envelope != hashlib")


# ---------------------------------------------------------------------------
# Primitive-cost model (word-level). Reports the conventional two-compress
# budget so candidates can be compared on the same accounting.
# ---------------------------------------------------------------------------

@dataclass
class Cost:
    add: int = 0
    xor: int = 0
    and_: int = 0
    not_: int = 0
    rot: int = 0
    shr: int = 0

    def plus(self, other: "Cost") -> "Cost":
        return Cost(
            add=self.add + other.add,
            xor=self.xor + other.xor,
            and_=self.and_ + other.and_,
            not_=self.not_ + other.not_,
            rot=self.rot + other.rot,
            shr=self.shr + other.shr,
        )

    def scale(self, n: int) -> "Cost":
        return Cost(
            add=self.add * n,
            xor=self.xor * n,
            and_=self.and_ * n,
            not_=self.not_ * n,
            rot=self.rot * n,
            shr=self.shr * n,
        )

    @property
    def primitives(self) -> int:
        return self.add + self.xor + self.and_ + self.not_ + self.rot + self.shr

    def as_dict(self) -> dict:
        return {
            "add": self.add,
            "xor": self.xor,
            "and": self.and_,
            "not": self.not_,
            "rot": self.rot,
            "shr": self.shr,
            "primitives": self.primitives,
        }


def cost_sigma(w: int) -> Cost:
    # two rot + one shr + two xor  (σ0 / σ1)
    return Cost(xor=2, rot=2, shr=1)


def cost_big_sigma() -> Cost:
    return Cost(xor=2, rot=3)


def cost_one_round(p: Params) -> Cost:
    c = cost_big_sigma().plus(cost_big_sigma())  # Σ0, Σ1
    if p.use_ch_maj:
        # Ch: e&f, ~e, (~e)&g, xor   ;  Maj: 3 and, 2 xor
        c = c.plus(Cost(and_=2, not_=1, xor=1))
        c = c.plus(Cost(and_=3, xor=2))
    else:
        c = c.plus(Cost(xor=2))  # e^f^g
        c = c.plus(Cost(xor=2))  # a^b^c
    # temp1: 4 adds; temp2: 1 add; new_e: 1 add; new_a: 1 add
    c = c.plus(Cost(add=7))
    return c


def cost_schedule(p: Params) -> Cost:
    if not p.use_schedule or p.rounds <= 16:
        return Cost()
    extra = p.rounds - 16
    one = cost_sigma(p.w).plus(cost_sigma(p.w)).plus(Cost(add=3))
    return one.scale(extra)


def cost_compress(p: Params) -> Cost:
    # Davies-Meyer feed-forward: `words` adds
    return cost_schedule(p).plus(cost_one_round(p).scale(p.rounds)).plus(Cost(add=p.words))


def cost_F(p: Params) -> Cost:
    return cost_compress(p).scale(2)


def conventional_budget(p: Params, iterations: int) -> dict:
    """Work to walk the orbit the usual way: n evaluations of F plus n XORs."""
    f = cost_F(p)
    total = f.scale(iterations).plus(Cost(xor=p.words * iterations))
    return {
        "F_evals": iterations,
        "compressions": 2 * iterations,
        "rounds": 2 * iterations * p.rounds,
        "cost": total.as_dict(),
        "sequential_depth_rounds": 2 * iterations * p.rounds,
        "state_bits": p.state_bits,
        "memory_words": p.words * 2 + 16 + max(p.rounds, 16),
    }
