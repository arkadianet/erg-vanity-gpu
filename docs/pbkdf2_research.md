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
| H3 | Specializing the HMAC-64 padded block (fixed W[8..15], first expand, K+W fold) reduces *work*. | **Implemented.** Algebra: first expand drops 32σ+48add → 22σ+35add (−10σ −13add per compress). Later expands are dense. Static op-count ≈ **2.5–3.5%** of a compression. Claims of “50% of the schedule / 25–30% overall” from public writeups do not survive this accounting. |
| H4 | Midstate-compiled early rounds (I/O fixed for 2047 iters) save a full first round. | **Derived, not shipped.** Round 0: `T2` and the non-`W[0]` part of `T1` are constant. After round 0, six working variables are still the midstate. Round 1 still needs `Σ1(e)`, `Ch`, `Σ0(a)`, `Maj` on data-dependent `a,e`. Save ≈ one round in 80 (≈1.2%) plus a cheaper Ch/Maj in round 1. Not material. |
| H5 | Lockstep 2-wide evaluation of independent seeds improves *throughput* (ILP), not work. | **Implemented (CPU).** Same compressions, two independent ARX chains. |
| H6 | `x ⊕ HMAC(P,x)` cannot be fused cheaper than computing HMAC and XORing: the next iterate *is* the HMAC. | **Held.** |
| H7 | Adjacent BIP39 mnemonics share prefixes, so ipad/opad work can be shared. | **True but irrelevant.** Shared prefix only affects the 2 init compressions (`<0.1%`). `I` and `O` mix the whole key; the 4094-loop midstates differ. |
| H8 | Making `1536` a source-level constant (instead of `(total_len+64)*8`) lets a compiler DCE the first expand. | **Done** by writing the specialized expand explicitly. Previous GPU hot path passed `total_len` as a value even though it was always 128. |

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

### Not revisited without new evidence

- Skipping or pairing HMAC iterations
- Fusing inner+outer into <160 rounds
- Folding post-σ constant additives into `K[t]`
- Sharing loop work across nearby mnemonics
- “Trim W[8..15] saves 50% of the schedule”
