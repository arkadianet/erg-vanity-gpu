// Research-only HMAC-64 A/B. Not concatenated into vanity/bench programs.
// -D RESEARCH_VARIANT=0  production rotate + generic expand
// -D RESEARCH_VARIANT=1  SHF-pair rotate + generic expand
// -D RESEARCH_VARIANT=2  SHF-pair + bitselect + HMAC-64 first expand
//
// Author: arkadianet

#ifndef RESEARCH_VARIANT
#define RESEARCH_VARIANT 0
#endif

__constant ulong K512[80] = {
    0x428a2f98d728ae22ul, 0x7137449123ef65cdul, 0xb5c0fbcfec4d3b2ful, 0xe9b5dba58189dbbcul,
    0x3956c25bf348b538ul, 0x59f111f1b605d019ul, 0x923f82a4af194f9bul, 0xab1c5ed5da6d8118ul,
    0xd807aa98a3030242ul, 0x12835b0145706fbeul, 0x243185be4ee4b28cul, 0x550c7dc3d5ffb4e2ul,
    0x72be5d74f27b896ful, 0x80deb1fe3b1696b1ul, 0x9bdc06a725c71235ul, 0xc19bf174cf692694ul,
    0xe49b69c19ef14ad2ul, 0xefbe4786384f25e3ul, 0x0fc19dc68b8cd5b5ul, 0x240ca1cc77ac9c65ul,
    0x2de92c6f592b0275ul, 0x4a7484aa6ea6e483ul, 0x5cb0a9dcbd41fbd4ul, 0x76f988da831153b5ul,
    0x983e5152ee66dfabul, 0xa831c66d2db43210ul, 0xb00327c898fb213ful, 0xbf597fc7beef0ee4ul,
    0xc6e00bf33da88fc2ul, 0xd5a79147930aa725ul, 0x06ca6351e003826ful, 0x142929670a0e6e70ul,
    0x27b70a8546d22ffcul, 0x2e1b21385c26c926ul, 0x4d2c6dfc5ac42aedul, 0x53380d139d95b3dful,
    0x650a73548baf63deul, 0x766a0abb3c77b2a8ul, 0x81c2c92e47edaee6ul, 0x92722c851482353bul,
    0xa2bfe8a14cf10364ul, 0xa81a664bbc423001ul, 0xc24b8b70d0f89791ul, 0xc76c51a30654be30ul,
    0xd192e819d6ef5218ul, 0xd69906245565a910ul, 0xf40e35855771202aul, 0x106aa07032bbd1b8ul,
    0x19a4c116b8d2d0c8ul, 0x1e376c085141ab53ul, 0x2748774cdf8eeb99ul, 0x34b0bcb5e19b48a8ul,
    0x391c0cb3c5c95a63ul, 0x4ed8aa4ae3418acbul, 0x5b9cca4f7763e373ul, 0x682e6ff3d6b2b8a3ul,
    0x748f82ee5defb2fcul, 0x78a5636f43172f60ul, 0x84c87814a1f0ab72ul, 0x8cc702081a6439ecul,
    0x90befffa23631e28ul, 0xa4506cebde82bde9ul, 0xbef9a3f7b2c67915ul, 0xc67178f2e372532bul,
    0xca273eceea26619cul, 0xd186b8c721c0c207ul, 0xeada7dd6cde0eb1eul, 0xf57d4f7fee6ed178ul,
    0x06f067aa72176fbaul, 0x0a637dc5a2c898a6ul, 0x113f9804bef90daeul, 0x1b710b35131c471bul,
    0x28db77f523047d84ul, 0x32caab7b40c72493ul, 0x3c9ebe0a15c9bebcul, 0x431d67c49c100d4cul,
    0x4cc5d4becb3e42b6ul, 0x597f299cfc657e2aul, 0x5fcb6fab3ad6faecul, 0x6c44198c4a475817ul
};

#if RESEARCH_VARIANT >= 1
inline uint shf_r32(uint lo, uint hi, uint n) {
    return (lo >> n) | (hi << (32u - n));
}
inline ulong ror64_shf(ulong x, uint n) {
    uint2 v = as_uint2(x);
    uint2 r;
    if (n < 32u) {
        r.x = shf_r32(v.x, v.y, n);
        r.y = shf_r32(v.y, v.x, n);
    } else {
        uint k = n - 32u;
        r.x = shf_r32(v.y, v.x, k);
        r.y = shf_r32(v.x, v.y, k);
    }
    return as_ulong(r);
}
inline ulong shr64_shf(ulong x, uint n) {
    uint2 v = as_uint2(x);
    uint2 r;
    r.x = shf_r32(v.x, v.y, n);
    r.y = v.y >> n;
    return as_ulong(r);
}
#define ROTR64(x, n) ror64_shf((x), (uint)(n))
#define SIG0_64(x) (ror64_shf((x), 1u) ^ ror64_shf((x), 8u) ^ shr64_shf((x), 7u))
#define SIG1_64(x) (ror64_shf((x), 19u) ^ ror64_shf((x), 61u) ^ shr64_shf((x), 6u))
#define EP0_64(x)  (ror64_shf((x), 28u) ^ ror64_shf((x), 34u) ^ ror64_shf((x), 39u))
#define EP1_64(x)  (ror64_shf((x), 14u) ^ ror64_shf((x), 18u) ^ ror64_shf((x), 41u))
#else
#define ROTR64(x, n) rotate((x), (ulong)(64ul - (n)))
#define SIG0_64(x) (ROTR64((x), 1) ^ ROTR64((x), 8) ^ ((x) >> 7))
#define SIG1_64(x) (ROTR64((x), 19) ^ ROTR64((x), 61) ^ ((x) >> 6))
#define EP0_64(x)  (ROTR64((x), 28) ^ ROTR64((x), 34) ^ ROTR64((x), 39))
#define EP1_64(x)  (ROTR64((x), 14) ^ ROTR64((x), 18) ^ ROTR64((x), 41))
#endif

#if RESEARCH_VARIANT >= 2
#define CH64(x, y, z)  bitselect((z), (y), (x))
#define MAJ64(x, y, z) bitselect((x), (y), ((x) ^ (z)))
#else
#define CH64(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#endif

#define SHA512_R(a, b, c, d, e, f, g, h, k, w) \
    do { \
        h += EP1_64(e) + CH64(e, f, g) + (k) + (w); \
        d += h; \
        h += EP0_64(a) + MAJ64(a, b, c); \
    } while (0)

#define SHA512_ROUNDS16(base) \
    do { \
        SHA512_R(a, b, c, d, e, f, g, h, K512[(base) + 0],  w0); \
        SHA512_R(h, a, b, c, d, e, f, g, K512[(base) + 1],  w1); \
        SHA512_R(g, h, a, b, c, d, e, f, K512[(base) + 2],  w2); \
        SHA512_R(f, g, h, a, b, c, d, e, K512[(base) + 3],  w3); \
        SHA512_R(e, f, g, h, a, b, c, d, K512[(base) + 4],  w4); \
        SHA512_R(d, e, f, g, h, a, b, c, K512[(base) + 5],  w5); \
        SHA512_R(c, d, e, f, g, h, a, b, K512[(base) + 6],  w6); \
        SHA512_R(b, c, d, e, f, g, h, a, K512[(base) + 7],  w7); \
        SHA512_R(a, b, c, d, e, f, g, h, K512[(base) + 8],  w8); \
        SHA512_R(h, a, b, c, d, e, f, g, K512[(base) + 9],  w9); \
        SHA512_R(g, h, a, b, c, d, e, f, K512[(base) + 10], w10); \
        SHA512_R(f, g, h, a, b, c, d, e, K512[(base) + 11], w11); \
        SHA512_R(e, f, g, h, a, b, c, d, K512[(base) + 12], w12); \
        SHA512_R(d, e, f, g, h, a, b, c, K512[(base) + 13], w13); \
        SHA512_R(c, d, e, f, g, h, a, b, K512[(base) + 14], w14); \
        SHA512_R(b, c, d, e, f, g, h, a, K512[(base) + 15], w15); \
    } while (0)

#define SHA512_EXPAND16() \
    do { \
        w0  += SIG1_64(w14) + w9  + SIG0_64(w1); \
        w1  += SIG1_64(w15) + w10 + SIG0_64(w2); \
        w2  += SIG1_64(w0)  + w11 + SIG0_64(w3); \
        w3  += SIG1_64(w1)  + w12 + SIG0_64(w4); \
        w4  += SIG1_64(w2)  + w13 + SIG0_64(w5); \
        w5  += SIG1_64(w3)  + w14 + SIG0_64(w6); \
        w6  += SIG1_64(w4)  + w15 + SIG0_64(w7); \
        w7  += SIG1_64(w5)  + w0  + SIG0_64(w8); \
        w8  += SIG1_64(w6)  + w1  + SIG0_64(w9); \
        w9  += SIG1_64(w7)  + w2  + SIG0_64(w10); \
        w10 += SIG1_64(w8)  + w3  + SIG0_64(w11); \
        w11 += SIG1_64(w9)  + w4  + SIG0_64(w12); \
        w12 += SIG1_64(w10) + w5  + SIG0_64(w13); \
        w13 += SIG1_64(w11) + w6  + SIG0_64(w14); \
        w14 += SIG1_64(w12) + w7  + SIG0_64(w15); \
        w15 += SIG1_64(w13) + w8  + SIG0_64(w0); \
    } while (0)

#if RESEARCH_VARIANT >= 2
#define SHA512_HMAC64_PAD      0x8000000000000000ul
#define SHA512_HMAC64_LEN      1536ul
#define SHA512_HMAC64_SIG0_PAD 0x4180000000000000ul
#define SHA512_HMAC64_SIG1_LEN 0x00c0000000003018ul
#define SHA512_HMAC64_SIG0_LEN 0x030aul
#define SHA512_HMAC64_K8       0x5807aa98a3030242ul
#define SHA512_HMAC64_K15      0xc19bf174cf692c94ul
#define SHA512_EXPAND16_HEAD() \
    do { \
        w0  += SIG0_64(w1); \
        w1  += SHA512_HMAC64_SIG1_LEN + SIG0_64(w2); \
        w2  += SIG1_64(w0) + SIG0_64(w3); \
        w3  += SIG1_64(w1) + SIG0_64(w4); \
        w4  += SIG1_64(w2) + SIG0_64(w5); \
        w5  += SIG1_64(w3) + SIG0_64(w6); \
        w6  += SIG1_64(w4) + SHA512_HMAC64_LEN + SIG0_64(w7); \
        w7  += SIG1_64(w5) + w0 + SHA512_HMAC64_SIG0_PAD; \
        w8  += SIG1_64(w6) + w1; \
        w9  += SIG1_64(w7) + w2; \
        w10 += SIG1_64(w8) + w3; \
        w11 += SIG1_64(w9) + w4; \
        w12 += SIG1_64(w10) + w5; \
        w13 += SIG1_64(w11) + w6; \
        w14 += SIG1_64(w12) + w7 + SHA512_HMAC64_SIG0_LEN; \
        w15 += SIG1_64(w13) + w8 + SIG0_64(w0); \
    } while (0)
#define SHA512_ROUNDS16_HEAD() \
    do { \
        SHA512_R(a, b, c, d, e, f, g, h, K512[0],  w0); \
        SHA512_R(h, a, b, c, d, e, f, g, K512[1],  w1); \
        SHA512_R(g, h, a, b, c, d, e, f, K512[2],  w2); \
        SHA512_R(f, g, h, a, b, c, d, e, K512[3],  w3); \
        SHA512_R(e, f, g, h, a, b, c, d, K512[4],  w4); \
        SHA512_R(d, e, f, g, h, a, b, c, K512[5],  w5); \
        SHA512_R(c, d, e, f, g, h, a, b, K512[6],  w6); \
        SHA512_R(b, c, d, e, f, g, h, a, K512[7],  w7); \
        SHA512_R(a, b, c, d, e, f, g, h, SHA512_HMAC64_K8,  0ul); \
        SHA512_R(h, a, b, c, d, e, f, g, K512[9],  0ul); \
        SHA512_R(g, h, a, b, c, d, e, f, K512[10], 0ul); \
        SHA512_R(f, g, h, a, b, c, d, e, K512[11], 0ul); \
        SHA512_R(e, f, g, h, a, b, c, d, K512[12], 0ul); \
        SHA512_R(d, e, f, g, h, a, b, c, K512[13], 0ul); \
        SHA512_R(c, d, e, f, g, h, a, b, K512[14], 0ul); \
        SHA512_R(b, c, d, e, f, g, h, a, SHA512_HMAC64_K15, 0ul); \
    } while (0)
#endif

inline ulong8 research_compress_pad64(ulong8 mid, ulong8 msg) {
    ulong w0 = msg.s0, w1 = msg.s1, w2 = msg.s2, w3 = msg.s3;
    ulong w4 = msg.s4, w5 = msg.s5, w6 = msg.s6, w7 = msg.s7;
    ulong w8 = 0x8000000000000000ul;
    ulong w9 = 0ul, w10 = 0ul, w11 = 0ul, w12 = 0ul, w13 = 0ul, w14 = 0ul;
    ulong w15 = 1536ul;
    ulong a = mid.s0, b = mid.s1, c = mid.s2, d = mid.s3;
    ulong e = mid.s4, f = mid.s5, g = mid.s6, h = mid.s7;
#if RESEARCH_VARIANT >= 2
    SHA512_ROUNDS16_HEAD();
    SHA512_EXPAND16_HEAD();
#else
    SHA512_ROUNDS16(0);
    SHA512_EXPAND16();
#endif
    SHA512_ROUNDS16(16);
    SHA512_EXPAND16();
    SHA512_ROUNDS16(32);
    SHA512_EXPAND16();
    SHA512_ROUNDS16(48);
    SHA512_EXPAND16();
    SHA512_ROUNDS16(64);
    return (ulong8)(mid.s0 + a, mid.s1 + b, mid.s2 + c, mid.s3 + d,
                    mid.s4 + e, mid.s5 + f, mid.s6 + g, mid.s7 + h);
}

inline ulong8 research_hmac64(ulong8 inner, ulong8 outer, ulong8 msg) {
    return research_compress_pad64(outer, research_compress_pad64(inner, msg));
}

__kernel void research_hmac64_loop(
    __global const ulong* inner,
    __global const ulong* outer,
    __global const ulong* u0,
    uint iters,
    __global ulong* out
) {
    uint gid = get_global_id(0);
    ulong8 i = vload8(0, inner);
    ulong8 o = vload8(0, outer);
    ulong8 u = vload8(gid, u0);
    ulong8 acc = u;
    for (uint n = 1u; n < iters; n++) {
        u = research_hmac64(i, o, u);
        acc ^= u;
    }
    vstore8(acc, gid, out);
}
