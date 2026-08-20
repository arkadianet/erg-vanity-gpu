# PBKDF2-HMAC-SHA512 research log

Author: arkadianet

The existing GPU/CPU implementations are a **baseline**, not a design constraint.
This log records hypotheses, derivations, implementations, correctness, and
benchmarks so closed avenues are not revisited.

## Objective

Find a materially more efficient way to compute the **exact**
PBKDF2-HMAC-SHA512 result (bit-for-bit), or show that the explored
transformations cannot reduce the required work.

Workload that matters: BIP39 seed derivation (`c = 2048`, `dkLen = 64`,
salt = `"mnemonic"` + passphrase, password = mnemonic bytes or SHA-512(mnemonic)
if longer than 128). The formulation itself is not restricted to one GPU.

## Formalization

RFC 8018 / BIP39:

```
U_1 = HMAC-SHA512(P, S || INT32_BE(i))
U_j = HMAC-SHA512(P, U_{j-1})          j = 2..c
T_i = U_1 ⊕ U_2 ⊕ ... ⊕ U_c
DK  = T_1 || T_2 || ...                (BIP39 uses only T_1)
```

HMAC (RFC 2104), with `B = 128`, `K'` = `P` padded to `B` or `SHA-512(P)` if
`|P| > B`:

```
HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
```

SHA-512 compression is Davies–Meyer with SHACAL-2:

```
Compress(H, M) = E_M(H) + H     (eight 64-bit words, + is mod 2^64)
```

Write `I = Compress(IV, K' ⊕ ipad)` and `O = Compress(IV, K' ⊕ opad)`.
For every 64-byte message `m` (all `U_j` and the outer hash of every HMAC):

```
pad64(m) = m || 0x80 || 0x00^55 || BE64(1536)
finalize(H, m) = Compress(H, pad64(m))
HMAC(K, m) = finalize(O, finalize(I, m))     // |m| = 64
```

The PBKDF2 inner loop is therefore a 2-step recurrence on 512-bit words:

```
inner_j = Compress(I, pad64(U_{j-1}))
U_j     = Compress(O, pad64(inner_j))
T       = ⊕_j U_j
```

Per BIP39 seed that is **2 + 2 + 2047×2 = 4098** SHA-512 compressions
(ipad, opad, U1 inner/outer, then 2047 HMAC-64s). The 2047×2 = 4094
HMAC-64 compressions dominate.

`pad64` is an invariant of the loop:

| Word | Value |
|------|--------|
| W[0..7] | message (the only variable) |
| W[8] | `0x8000000000000000` |
| W[9..14] | `0` |
| W[15] | `1536` |

A full 80-word schedule expansion from 10k random messages showed **only
W[8..15] are compile-time constants**. From W[16] onward every word depends
on the message. Constant *additives* still appear (e.g. `σ1(1536)` in W[17])
but they cannot be moved into `K[t]` without corrupting later schedule uses:
`σ` is linear over GF(2), not over `Z/2^64Z`, so `σ(x+C) ≠ σ(x)+σ(C)`.

## Hypotheses

| ID | Claim | Status |
|----|--------|--------|
| H1 | In the random-oracle model, `T = ⊕_{j=1}^{c} f^{j}(x)` requires `c` evaluations of `f`. No closed form skips HMAC evaluations. | **Held.** A shortcut here would be a distinguishing attack on HMAC-SHA512. Even iteration count (`c=2048`) cancels `⊕ O` if feed-forward were XOR; it is ADD, and the next iteration still needs the full `U_j`. |
| H2 | HMAC cannot be reduced below 2 sequential SHA-512 compressions without changing the function. | **Held.** Nested `H(O \|\| H(I \|\| m))` is the definition. Inner output is the outer message. |
| H3 | Specializing the HMAC-64 padded block (fixed W[8..15], first expand, K+W fold) reduces *work*. | **Implemented and measured.** Algebra: first expand 32σ+48add → 22σ+35add. CPU: **−3.2% to −3.5%** vs batched generic (two 24-seed runs). Public “25–30%” claims do not survive this accounting. |
| H4 | Midstate-compiled early rounds (I/O fixed for 2047 iters) save a full first round. | **Derived, not shipped.** Round 0: `T2` and the non-`W[0]` part of `T1` are constant. After round 0, six working variables are still the midstate. Round 1 still needs `Σ1(e)`, `Ch`, `Σ0(a)`, `Maj` on data-dependent `a,e`. Save ≈ one round in 80 (≈1.2%) plus a cheaper Ch/Maj in round 1. Not material. |
| H5 | Lockstep 2-wide evaluation of independent seeds improves *throughput* (ILP), not work. | **Implemented (CPU). Loss.** +11% ns/seed vs specialized single. Same work, worse throughput here. |
| H6 | `x ⊕ HMAC(P,x)` cannot be fused cheaper than computing HMAC and XORing: the next iterate *is* the HMAC. | **Held.** |
| H7 | Adjacent BIP39 mnemonics share prefixes, so ipad/opad work can be shared. | **True but irrelevant.** Shared prefix only affects the 2 init compressions (`<0.1%`). `I` and `O` mix the whole key; the 4094-loop midstates differ. |
| H8 | Making `1536` a source-level constant (instead of `(total_len+64)*8`) lets a compiler DCE the first expand. | **Done** by writing the specialized expand explicitly. Previous GPU hot path passed `total_len` as a value even though it was always 128. |
| H9 | RTX SHF is 32-bit. A 64-bit ROTR is **exactly two SHF**; that is a hardware floor, not a coding style. | **Held.** Ampere/Turing `SHF.R` concatenates two 32-bit regs and extracts 32. Both halves of a 64-bit rotate need one SHF each. No 64-bit SHF exists. |
| H10 | Bitsliced SHA-512 eliminates SHF (rotates become wire permutes / SHFL) and is fundamentally better on RTX. | **Rejected.** SHA-512 is ARX. Bitsliced 64-bit add is a 64-step carry chain (or Θ(log 64) prefix plus more ops). 80×7×64 ripple steps ≫ 1550 SHF. Warp-split bitslice trades SHF for SHFL **and** a serial adder across lanes. Hashcat/John do not bitslice SHA-512. |
| H11 | Σ/σ can be computed with fewer than three 64-bit rotates via a different circulant basis. | **Rejected.** Weight-3 circulants `{28,34,39}` and `{14,18,41}` have no 0-offset and no 2-rotate form. Chaining `ROTR(ROTR(x,a),b)` uses the same 2 SHF per rotate. |
| H12 | Writing rotates as explicit 32-bit SHF (plus `bitselect` Ch/Maj) is the RTX-native execution of the same 80 rounds. | **Implemented.** Rust `sha512_u32` + OpenCL `ror64_shf`/`shr64_shf`. Floor **1550 SHF** per specialized HMAC-64 compression. `rotate(ulong)` is left to the compiler and may emit `shr.b64/shl.b64/or` (more than 2 SHF). |

## What is not a lower bound

“SHA-512 is designed to be expensive” is not a proof of optimality. The
distinctions used here:

- **Cryptographic lower bound:** you need all `c` HMAC evaluations and both
  nested hashes (H1, H2). That bounds *evaluations*, not *cost per evaluation*.
- **Known best implementations:** hashcat / John specialize ipad/opad midstates
  and the 64-byte HMAC block. They still run 80 rounds × 2 × 2047.
- **Conventional:** the previous tree already had midstates, ulong8 registers,
  and batched W-expand. It did **not** specialize the first expand or fold
  padding into `K`.

No published equivalent circuit evaluates full SHA-512 compression in fewer
than 80 rounds. ASIC/GPU miners do not skip rounds.

## Implementations

1. **`sha512_hmac64` (Rust + OpenCL)** — from-scratch compressor for `pad64`.
   First 16 rounds use `K[8]+PAD`, `K[15]+1536`, and `W=0` on rounds 9–14.
   First expand uses the derived identities (verified against the generic
   in-place expand on 10k random messages).
2. **`pbkdf2_fast`** — NMAC-style key (`I`,`O`) + HMAC-64 recurrence. `derive`
   now calls this. `derive_reference` keeps the old layered loop.
3. **`hmac64_x2` / `derive_pair`** — lockstep two-seed HMAC-64.
   GPU hot path (`hmac_sha512_msg64_u8`, BIP39 U1 outer) calls `sha512_hmac64`.
4. **`sha512_u32`** — same HMAC-64 compress on `(lo,hi)` 32-bit halves. This is
   the SHF-native machine: `shf_r(lo,hi,n) = (lo>>n)|(hi<<(32-n))`.
5. **OpenCL `ror64_shf` / `shr64_shf`** — all SHA-512 Σ/σ on the GPU use this
   instead of `rotate(ulong)`. Ch/Maj use `bitselect` (LOP3 on NVIDIA).

## Correctness

Trusted reference: `pbkdf2` crate (`pbkdf2_hmac::<Sha512>`), plus BIP39
vectors (`abandon`×11+`about`, empty and `TREZOR` passphrases).

Rust tests (see `sha512_hmac64`, `pbkdf2_fast`, `pbkdf2`):

- 400 random `(mid, msg)` triples: specialized = generic = `sha512::compress_block`
- MAJ/CH identities
- Schedule constants = `σ0(PAD)`, `σ1(1536)`, `σ0(1536)`, `K[8]+PAD`, `K[15]+1536`
- 250 random PBKDF2 cases (password 0–179 B, salt 0–139 B, iters in
  {1,2,3,8,16,64,128}, dkLen in {16,32,64,65,80,128})
- Official BIP39 vectors and a second 2048-iter mnemonic against the crate
- `derive_pair` = two singles
- generic-loop block = specialized block

GPU kernel tests are the existing OpenCL suite (`ERG_RUN_GPU_TESTS=1`); this
environment has no GPU, so those stay skipped here.

## Benchmarks

Command: `ERG_PBKDF2_BENCH=1 cargo test -p erg-vanity-crypto --release bench_candidates -- --nocapture`

Host: cloud agent VM, rustc 1.97.1, 24 seeds × 2048 iterations, two consecutive
runs (agreed to ~1%). An earlier 8-seed run on a contended VM was discarded
(~2.1 µs/seed, not repeatable).

| Candidate | ns/seed (run 1) | ns/seed (run 2) | vs batched generic |
|-----------|-----------------|-----------------|--------------------|
| specialized HMAC-64 | 867677 | 864827 | **−3.2% to −3.5%** |
| batched generic (previous GPU structure) | 899494 | 893442 | baseline work |
| W[80] table HMAC-64 | 934830 | 934595 | +4% to +5% (worse) |
| layered HMAC+alloc (old CPU `derive`) | 2399240 | 2409789 | alloc-dominated, not algorithmic |
| interleaved pair / 2 | 967045 | 967246 | **+11% worse than spec** |

The measured −3.3% matches the static first-expand accounting (32σ+48add →
22σ+35add, plus eight padding-round folds). It is **not** the 25–30% claimed
by some public “trim half the schedule” writeups.

GPU isolated PBKDF2 was ~1600 ns/seed on RTX 3080 Ti under the previous
kernel. This environment has no GPU. Expect the OpenCL `sha512_hmac64` port
to move isolated time by about the same few percent if the NVIDIA compiler
was not already folding `(total_len+64)*8`; re-measure on hardware.

## Conclusions

Outcome **(3)**: the explored exact transformations cannot materially reduce
the required computation.

- **Evaluations are a floor.** `c` HMAC calls and 2 compressions per HMAC are
  required for bit-identical PBKDF2-HMAC-SHA512 (H1, H2). BIP39 is 4094
  HMAC-64 compressions plus 4 setup/U1 compressions. XOR-of-iterates has no
  cheaper closed form (H6). Shared mnemonic prefixes do not touch the loop (H7).
- **The only remaining exact work reduction inside those compressions** is
  specializing `pad64` (H3). We derived it, implemented it from scratch,
  differential-tested it, and measured **~3.3%** vs the previous batched
  W-expand compressor. That is the size of the algebraic leftover, not an
  implementation accident.
- **H4** (midstate-compiled round 0) is ≤1.2% and was not shipped.
- **H5** (2-wide lockstep) increased CPU time by ~11%. It does not reduce
  work. A GPU 2-wide kernel is still a hardware-specific occupancy bet, not
  an algorithmic one.

The production path now *is* the HMAC-64 formulation (Rust `derive` + OpenCL
hot path). That is the right structure. It is not a new asymptotic, and it
does not justify treating ~1.6 µs/seed as a cryptographic lower bound — only
as “4094 specialized pad64 compressions,” which is what the math requires
unless SHA-512 compression itself is implemented with fewer than 80 rounds
of ARX (no known equivalent circuit).

## SHA-512 execution and RTX SHF

Given H1–H3, the remaining question is whether those 4094 compressions can
be *executed* with fewer SHF than the conventional 80-round `ulong` form.

### Cost of one specialized HMAC-64 compression

| Piece | Rotates / shifts | SHF (2 per ROTR64, 1 per SHR-half) |
|-------|------------------|-------------------------------------|
| 80 × Σ0 | 80 × 3 ROTR | 480 |
| 80 × Σ1 | 80 × 3 ROTR | 480 |
| first expand (specialized) | 22 σ-like | 110 |
| 3 dense expands | 3 × 16 × (σ0+σ1) | 480 |
| **Total** | | **1550** (`HMAC64_SHF_FLOOR`) |

64-bit ADD is 2× 32-bit IADD + carry (cheap on Ampere). Ch/Maj are LOP3
(`bitselect`), not SHF.

`4094 × 1550 ≈ 6.35e6` SHF per BIP39 seed is the rotate/shift floor if every
ROTR is a clean 2-SHF pair.

### Why bitslice is not the SHF escape

Bitslice makes ROTR a permute of bit-position registers (0 SHF). SHA-512
still needs 64-bit **add**. In bitslice that is a 64-step ripple carry
(verified: `bitslice_add_ripple(u64::MAX, 1)` is 64 steps and wraps to 0).
Per compression, ~80×7 adds × 64 steps is tens of thousands of sequential
carry ops, two orders of magnitude above 1550 SHF. A warp-split layout
moves bit positions into SHFL; the adder remains serial across lanes.
This is why production SHA-512 kernels stay word-parallel.

### What we changed

OpenCL no longer uses `rotate(ulong)` / `x >> 7` for Σ/σ. It uses
`ror64_shf` / `shr64_shf` so the SASS we want is the 32-bit SHF pattern
John/hashcat already rely on for NVIDIA. The Rust `sha512_u32` compressor
is the same mapping and matches `compress_hmac64` on 200 random blocks.

### Outcome

**No formulation of exact SHA-512 on RTX uses fewer than 2 SHF per 64-bit
rotate.** Bitslicing removes SHF and loses on add. Σ/σ have no lower-weight
rotate basis. The conventional 80-round structure *is* the SHF-optimal
exact structure; the only RTX-specific win is making those rotates compile
to the 2-SHF floor instead of a 64-bit shift/shift/or expansion.

Re-measure isolated PBKDF2 on an RTX card. If `rotate(ulong)` was already
lowering to SHF, expect noise. If it was emitting `shr.b64`, expect a
real isolated-kernel gain with no change in hash values.

### Not revisited without new evidence

- Skipping or pairing HMAC iterations
- Fusing inner+outer into <160 rounds
- Folding post-σ constant additives into `K[t]`
- Sharing loop work across nearby mnemonics
- “Trim W[8..15] saves 50% of the schedule”
- Bitsliced SHA-512 on GPU (carry-chain argument)
- Weight-2 Σ/σ identities
