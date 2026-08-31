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
| H13 | Two SHA-512 rounds fuse to a cheaper equivalent circuit. | **Rejected.** `fused_two_rounds` is bit-identical to two steps and contains the same 4 Σ, 2 Ch, 2 Maj, and 14 adds. Word-level hash-cons DAG: 2/4/8 rounds are exact multiples of one round (no shared Σ/Ch/Maj/add nodes). |
| H14 | A different 64-bit basis makes both ADD and ROTR cheap. | **Rejected.** ROTR is F₂-linear and not ℤ/2⁶⁴ℤ-linear (fails on a majority of random words). ADD is not F₂-linear. 3:2 CSA then ROTR both halves is not ROTR of the sum (64/79 random triples). No joint representation that is exact and cheaper; conversion before every Σ reintroduces a CPA. |
| H15 | Carry-save T1 reduces work. | **Equivalent, cost-shifting.** `t1_csa` matches four adds on 400 random 5-tuples. Each of 3 CSA needs a 64-bit `<<1` = 2 SHF → **+480 SHF / compression** on RTX. Delay win in FPGA papers; more SHF here. |
| H16 | Digit-slice / mixed radix is a viable middle ground between word-parallel and bitslice. | **Rejected as a new machine.** All 12 Σ/σ distances are distinct. Radix 4 frees 2/12 rotates and costs 8960 nibble-adds; radix 8 frees 1/12 and costs 4480 byte-adds. RTX already is radix 32 (2× IADD, 0 free rotates) — that is H12, not a new formulation. |
| H17 | Inner/outer midstates allow more than round-0 PE. | **Implemented (`compress_hmac64_pe`).** Round 0 is affine in `W[0]`. Round 1 Ch/Maj collapse to one AND + XOR with constants (`ch_fixed_yz` / `maj_fixed_yz`). After that every working variable is message-dependent. Save 2 Σ + Ch + Maj per compression ≈ **1.2%**. Differential-tested vs `compress_hmac64` on 200 blocks. Not shipped. |
| H18 | `T = ⊕_j (E_j(O) + O)` or the U-chain has a closed form. | **Rejected.** `(X+C) ⊕ (Y+C) ≠ X ⊕ Y`. HMAC-64 is not a homomorphism over `+` or `⊕` (tested). `f¹⊕f²⊕f³` does not collapse to a function of `x` cheaper than the three images. |
| H19 | The pad64 schedule has hidden identities after the first expand. | **Rejected.** Const-folded schedule DAG: first expand is exactly 22 σ (44 ror + 22 shr); three dense expands add exactly 192 ror + 96 shr (no extra CSE). For 80 random messages, no `W[t]` (`t≥32`) equals `W[s]`, `W[s]+C`, `σ0(W[s])`, or `σ1(W[s])`. σ0 and σ1 of the same word share no rotate distances. |
| H20 | Published SHA-2 / PBKDF2 / ARX work contains an exact 10%+ evaluation shortcut. | **Rejected after reading.** See literature section. Every claimed large speedup is midstates (already in the 4094 count), ZB/IS (our ~3%), register packing, SIMD of independent blocks, or critical-path/area — not fewer fundamental ops. |
| H21 | Automated search can find a 2-rotate equivalent for Σ or for `Σ+Ch` (the ~10% SHF path). | **Rejected in the searched class.** Exhaustive 2-term+shift vs Σ0/Σ1 on all basis vectors: empty. 15 structured fusions: 0/400. Superopt 12k steps: no rotate dropped. Mendel form = same circuit. Related-mnemonic I/O Hamming >180. |
| H22 | N independent BIP39 PBKDF2 instances cost materially less than N× one instance (shared salt, bitslice, prefix add, last-word family, warp-as-one-circuit). | **Rejected as a conventional-DAG claim.** Shared nodes are O(1). That does **not** bound every algorithm for `C_N` — only the product of N scalar SHA DAGs. See H23. |
| H23 | A change of computational basis (FFT/Walsh, packing, polynomial/multipoint, mixed-instance SLP, batch-inversion analog, warp-as-one-object) evaluates `C_N` at ≤ 0.9 N · Work(C) without sharing scalar intermediates. | **Rejected for every hook known to beat N×.** Independent ANDs have multiplicative complexity N (exhaustive N=2). Walsh/FFT across instances computes the wrong function and costs extra. Fast multipoint needs a dense high-degree univariate SHA does not provide. SWAR packing costs more word-ops than two native adds. MiniARX-4 mixed superopt: 0/8000 programs cheaper than 2×. Polarization fails for MiniSHA-8 and HMAC-64. Bit-major MiniARX (`arx_basis`) loses on the GPU cost model. See basis section. |

## What is not a lower bound

“SHA-512 is designed to be expensive” is not a proof of optimality. The
distinctions used here:

- **Cryptographic lower bound:** you need all `c` HMAC evaluations and both
  nested hashes (H1, H2, H18). That bounds *evaluations*, not *cost per
  evaluation*.
- **Circuit lower bound:** we do not have `Size(f^N) ≥ N Size(f)` for
  arbitrary Boolean circuits (direct-sum is open). H13–H17, H19 attack
  the conventional 80-round circuit. H22 bounds the *product DAG*.
  H23 classifies the representations that *do* beat N× on other
  functions and shows SHA-512/PBKDF2 has none of those hooks.
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
6. **`sha512_algebra`** — research-only: fused 2-round formula, CSA T1,
   midstate PE compressor, word-level CSE DAG, Ch/Maj one-var identities.
   Not on the production path.
7. **`sha512_search`** — research-only automated discovery: exhaustive
   2-term Σ search, structured Σ+Ch fusions, 8-bit ADD+ROTR correction,
   STOKE-style superopt of `Σ1+Ch`, Mendel form, related-mnemonic midstate
   Hamming. Not on the production path.
8. **`pbkdf2_batch`** — conventional-DAG batch accounting and tests.
   Production `derive` is unchanged.
9. **`pbkdf2_basis`** — change-of-basis / collective-evaluation attacks
   on `C_N` (FFT/Walsh, multipoint, batch inversion analog, mixed MiniARX,
   independent ANDs). Production `derive` is unchanged.
10. **`arx_basis`** — bit-major MiniARX vs word-major (Kogge–Stone /
    ripple / hybrid-Σ). Loses on a GPU/AVX-512 cost model. Production
    `derive` is unchanged.

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
- `sha512_algebra`: PE = production on 200 blocks; CSA T1 = four adds on
  400 tuples; fused 2-round = two steps; HMAC not a homomorphism; schedule
  DAG σ-count; no `W[t]` identities after the first expand; DAG 1/2/4/8-round
  scaling; ROTR/ADD/CSA-rotate non-identities
- `sha512_search`: no 2-term Σ; structured fusions 0/400; superopt keeps
  3 rotates; 8-bit ADD+ROTR correction dense; Mendel = standard `a'`;
  related-mnemonic midstates avalanche; MiniSHA-8 2-round = composed
- `pbkdf2_batch`: U1-inner W is salt-only and matches production U1;
  last-word prefix 8–11 rounds; family/unrelated shared ratios ≪ 0.1%;
  0 colliding HMAC-64 words over 8 steps for related and unrelated pairs;
  bitslice/KS/hybrid-transpose work > hardware IADD

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

Outcome **(3)**, now against a wider attack surface: no exact formulation we
could write down, prove equivalent, and measure cuts the work by 10% or more.

This is not “SHA-512 is designed to be expensive.” It is a claim about
specific doors.

**Is ~4094 compressions fundamental, or only conventional packaging?**

After ipad/opad precomputation, HMAC-SHA512 of a 64-byte string *is* two
Merkle–Damgård compressions of `pad64` blocks. That is the definition of
SHA-512 on `(128-byte prefix already consumed) || 64-byte U || 64-byte
padding`, not an implementation choice. PBKDF2 then needs
`T = ⊕_{j=1}^{c} f^{j}(U₁)` with `f = HMAC_K`. The 2047 remaining `f`
evaluations are 4094 compressions.

Reducing that *count* requires either

1. a closed form for the HMAC iterate-XOR, or
2. a bit-identical SHA-512 compression that is materially cheaper than 80
   ARX rounds (including the already-specialized first expand).

(1) fails: `f` is not a homomorphism; Davies–Meyer `+ O` does not cancel
under XOR; there is no cheap expression for `⊕_j f^j` (H1, H6, H18).
(2) fails under every equivalent circuit we constructed (H3 leftover is
~3%; H4/H17 is ~1.2%; H13–H16, H19 find no further cancellation).

So 4094 is fundamental **relative to those two absences**. It is not a
complexity-theoretic lower bound — nobody has one for SHA-512 evaluation —
but it is also not an artifact of writing the recurrence the usual way.

**What actually reduces work, in order:**

| Transform | Exact? | Size |
|-----------|--------|------|
| ipad/opad midstates (BR) | yes | 4c → 2c+2 compressions; this *is* the 4094 |
| `pad64` first-expand / ZB / IS (H3) | yes | **~3.3%** measured |
| Compiled round 0 + round-1 Ch/Maj (H4/H17) | yes | **~1.2%** accounting; not shipped |
| CSA / unroll / retiming / n-SMS / 2-wide | yes or N/A | same ops, sometimes worse throughput |

Nothing in that table is 10%, 25%, or 50%.

The production path remains specialized HMAC-64. Isolated RTX ~1.6 µs/seed
is still “4094 specialized pad64 compressions on the 1550-SHF machine,”
not a cryptographic minimum. A new equivalent circuit for SHA-512
compression would reopen (2). We did not find one.

## Deeper exact-evaluation attacks

Prototypes live in `crates/erg-vanity-crypto/src/sha512_algebra.rs`.
Every identity below was written as a map, checked for bit-identity or
refuted on random inputs, and costed.

### Algebra of one compression

SHA-512 is Davies–Meyer over SHACAL-2:

```
Compress(H, M) = E_M(H) + H     (eight words, + is mod 2^64)
```

The round is an 8-word shift register:

```
T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
T2 = Σ0(a) + Maj(a,b,c)
(a,e) ← (T1+T2, d+T1)
(b,c,d,f,g,h) ← (a,b,c,e,f,g)
```

Σ/σ are F₂-linear circulants. `+` is not. `Σ(x+y) ≠ Σ(x)+Σ(y)`, so a
round cannot be pushed through the previous round’s adds. Expanding two
rounds (`fused_two_rounds`) just writes `Σ1(d+T1)` and `Σ0(T1+T2)` — new
full Σ of new words. Same operation count. Equivalence tested on 200
random states.

A word-level hash-cons DAG (interned Ror/Shr/Xor/And/Add, commutative
XOR/AND/ADD, const-fold) counts unique nodes after *n* rounds. Counts
scale as exactly `n ×` one round for `n = 1,2,4,8`. Connecting the
`pad64` schedule does not share rotates with Σ: the twelve distances
`{28,34,39,14,18,41,1,8,7,19,61,6}` are pairwise distinct, so
`{Σ0,Σ1,σ0,σ1}(X)` never share a rotate of the same `X`.

Choi/Seo “BO” (IEEE Access 2021) packs four rounds of *stores* into one
register window. That is allocation, not algebra. Our `rnd` already does
it. FPGA “mega-rounds” (Athanasiou et al., IET 2013) unroll two rounds
and retime; they still perform 80 rounds of ARX and advertise *delay*
and area, including CSA on the critical path.

### Partial evaluation of the inner/outer maps

Per seed, `I` and `O` are constant for 2047 iterations. Inner compression
is SHACAL-2 with **fixed plaintext `I` and variable key `pad64(U)`**.

Round 0:

```
T1 = C0 + W[0]     (C0 = I_h + Σ1(I_e) + Ch(I_e,I_f,I_g) + K[0])
T2 = C1            (depends only on I_a,I_b,I_c)
a1 = C0+C1 + W[0]
e1 = I_d+C0 + W[0]
```

Round 1 sees `Ch(e1, I_e, I_f)` and `Maj(a1, I_a, I_b)`. With two
constants this is one AND and one XOR (`ch_fixed_yz`, `maj_fixed_yz`;
200-vector check). On RTX that is still one LOP3. Round 2’s Ch already
has two variable inputs. After that the state is fully mixed.

`compress_hmac64_pe` implements this and matches `compress_hmac64` on
200 random `(mid, msg)`. Work saved: 2 Σ + Ch + Maj out of 160 such
ops, plus a handful of adds ≈ 1.2% of a compression. Not 10%.

White-box / “compile the whole E_(·)(I)” for a 512-bit key is a 2⁵¹²
table. Useless.

### Schedule, again, from the DAG

Generic first expand: 32 σ. Const-folding `W[8]=PAD`, `W[9..14]=0`,
`W[15]=1536` leaves **22 σ** (44 ror + 22 shr). That is exactly
`expand16_hmac64`. The next 48 words add 192 ror + 96 shr with no
further sharing. Expanding the recurrence into a DAG from `W[0..7]`
does not beat computing each `W[t]` once: each word is used as `W[t]`,
`σ1` into `W[t+2]`, add into `W[t+7]`, `σ0` into `W[t+15]`, add into
`W[t+16]`.

If `+` were `⊕`, the schedule would be an F₂-linear map
`{0,1}⁵¹² → ({0,1}⁶⁴)⁶⁴` and a 64×512 matrix-vector product. That is
*more* work than the recurrence, and it is not SHA-512 because of
carries.

SHA-512 HMAC-64 is the *worst* SHA-2 for zero-based leftover: the inner
digest is 64 bytes in a 128-byte block, so only `W[9..14]` vanish.
SHA-256 HMAC has a 32-byte digest in a 64-byte block and therefore more
padding zeros (Choi ZB: 19 of 45 first-expand ops). Public “25–30% from
trimming W[8..15]” (ipsbruno3 / John #3525) counts words, not σ/add.

### HMAC, XOR accumulate, U-chain

```
f(m) = Compress(O, pad64(Compress(I, pad64(m))))
T    = ⊕_{j=1}^{2048} f^j(U₁)
```

`f` is not linear over `+` or `⊕` (`hmac64_not_a_homomorphism`).
If the feed-forward were XOR and `c` even, `⊕_j (E_j(O) ⊕ O)` would
drop `O` and still require every `E_j(O)`. The feed-forward is ADD, so
even that cancellation is false: `(X+O) ⊕ (Y+O) ≠ X ⊕ Y` (H18).

Iterating `f` is function composition, not a group operation. Addition
chains / matrix powering do not apply. A functional-graph lookup is
2⁵¹². Meet-in-the-middle still does ~c evaluations (and needs an
inverse of `f`, which is the expensive direction).

Inner then outer is 160 sequential rounds with an 8-word add in the
middle. The outer’s `W[0..7]` *are* the inner digest; they do not exist
until inner round 79 + feed-forward. No cancelled ops across the
boundary. Outer round 0 is the same PE as H17.

### Representations

| Representation | ADD | ROTR | Exact SHA-512? |
|----------------|-----|------|----------------|
| Standard words | native IADD | 2 SHF | yes (baseline) |
| Bitslice | 64-step ripple | wire permute | yes; ≫ 1550 SHF |
| nibble / byte slice | 16 / 8 digit-adds | most distances still bit-level | yes; worse than words, rotates not free |
| 32-bit halves | 2× IADD | 2× SHF.R | yes; this *is* RTX |
| Carry-save | cheap 3:2 | ROTR(s)+ROTR(c) ≠ ROTR(s+c) | only after CPA; +480 SHF if you CSA T1 |
| RNS | component ADD | not local | conversion each Σ destroys the gain |
| GF(2⁶⁴) | XOR, not integer add | not field mul | wrong algebra |

CLA / prefix adders increase gate count for parallelism. They do not
remove the 80×7 adds.

Boolean minimization: Ch/Maj are already one LOP3 (`bitselect`). NIST’s
best SHA-256 circuit is still ~22k AND gates; the adders dominate. A
flattened 80-round SHA-512 circuit does not CSE across distant rounds
(avalanche; our word DAG is the same fact at word granularity).

ARX cryptanalysis (rotational pairs, S-functions, ARXtools, truncated
addition, SHACAL-2 related-key rectangles out to 44/64 rounds) is about
*distinguishing or inverting*, not evaluating the forward function with
fewer ops. Bicliques reuse work across nearby *keys*; our U-chain
inputs are hash outputs, not a ball of related keys. Adjacent
mnemonics share only the 2 setup compressions (H7).

### Parallelism that reduces total work

Gueron/Krasnov n-SMS (eprint 2012/067): SIMD of several *independent*
schedules. Same arithmetic. Their SHA-512 2-SMS was ~3% or a loss.
Our 2-wide CPU path was **+11%**. Parallel `T_i` blocks do not exist
for BIP39 (`l = 1`). TMTO amortizes over many instances with one `f`;
each mnemonic has a different `(I,O)`.

### Literature (exact evaluation only)

| Source | What it actually saves |
|--------|------------------------|
| Choi/Seo IEEE Access 2021 (BR, IS, ZB, BO) | midstates; skip length checks; first-expand zeros; register packing. 39% vs OpenSSL is vs a layered HMAC, not vs specialized HMAC-64. |
| Visconti HMAC-SHA1 / WOOT16 hashcat | midstates + more padding zeros (20-byte digest). SHA-512 has fewer zeros. |
| ipsbruno3 / John #3525 “25–30%” | same ZB as H3; Magnum: immediates already beat a constant trim array. We measured **~3.3%**. |
| Gueron n-SMS | SIMD, not fewer ops. Last-block schedule precompute = our pad64. |
| Athanasiou FPGA SHA-512 | unroll + retiming + CSA: throughput/area, same 80 rounds. |
| Bitcoin SHA-256d ASICs | process + pipeline + midstate. Still 64×2 rounds. |
| Intel / ARM SHA-512 ISA | hardware 80-round compressor. |
| NIST circuit complexity (SHA-256) | ~22k AND after minimization. |
| SHACAL-2 attacks (44 of 64) | key recovery, not forward eval of 80-round SHA-512. |

No paper we found gives a bit-identical SHA-512 compression with
materially fewer than 80 ARX rounds, or a closed form for
`⊕ HMAC-SHA512^j`.

Mendel–Nikolić–Biryukov’s alternative description
`A_{t+1} = F(A_t,…,A_{t−6}) + A_{t−7} + W_t` is a **dependency-graph
rewrite**, not a cheaper circuit: `F` still contains both Σ, Ch, Maj, and
the same adds. `mendel_a_next` = `standard_a_next` on 200 random states.

## Automated discovery

The conventional rewrite space is exhausted. This pass searched for a
*different circuit* that computes the same map, including reduced-width
models and a superoptimizer. Production kernels were not changed.

The only local change that would hit ~10% SHF is **dropping one rotate
from each of Σ0 and Σ1**, 80 rounds × 2 Σ × 2 SHF = 320 SHF, 320/1550 ≈
21% if both lose a rotate, or 160/1550 ≈ 10% if each Σ loses one rotate
by fusing with Ch/Maj.

### What was searched

| Search | Domain | Result |
|--------|--------|--------|
| All 2-rotate maps, and 2-rotate + shift, vs Σ0/Σ1 | 64-bit, all 64 basis vectors | **no hit** (`two_term_sigma_search`) |
| `add(Σ,Ch)=add(Σ',Ch)` ⇒ Σ=Σ' | 8-bit, all `e` | identity, so adding Ch cannot drop a rotate |
| 15 structured fusions (rotate-through-add, xor-into-Σ, …) | 400 random 64-bit triples | **0 matches** |
| STOKE-style mutate of the `Σ1+Ch` SSA program | 12k steps, 8-bit samples | cost never went below 3 ror + 6 other |
| `ROTR_k(x+y)−(ROTR_k(x)+ROTR_k(y))` | 8-bit exhaustive, k=1..7 | equality on a minority of pairs; **every** input bit influences the correction |
| MiniSHA-8 two-round composition | 400 random | equals two one-rounds; no cancelled ops |
| Related 12-word mnemonics (last word differs) | real ipad/opad compress | I/O Hamming **>180 / 512** (avalanche) |

### Barriers (what would have to break)

**B1 — Iterate-XOR.** `f = HMAC_K` is not a homomorphism of `(F₂⁵¹²,⊕)`
or `(ℤ/2⁶⁴ℤ)⁸`. A closed form for `⊕_j f^j` is a structural break of
HMAC-SHA512.

**B2 — Compression count.** HMAC-64 is two Merkle–Damgård blocks.
One-compression HMAC on a 64-byte string is a different function.

**B3 — Σ as an F₂-linear map.** A weight-3 circulant is not in the
span of two rotates, or two rotates and a shift. Any equivalent that
uses ADD is no longer F₂-linear, so it cannot equal Σ.

**B4 — The 10% fused path.** Because `+ Ch` is injective in the Σ
argument, a cheaper `Σ'` plus the same Ch is not equivalent unless
`Σ'=Σ`. Non-linear mixes (feed Ch into a rotate, replace XOR with ADD
in Σ, …) failed the structured search and the superopt. A breakthrough
would be a 2-rotate circuit for `Σ1(e)+Ch(e,f,g)` that is *not* of the
form `Σ'(e)+Ch`. Exact synthesis of that 3-input 64-bit function is
open and currently out of reach; the 8-bit superopt did not find one.

**B5 — Joint ADD+ROTR.** The correction term depends on every operand
bit (8-bit exhaustive). A redundant encoding makes ADD cheap only if
you skip canonicalization; Σ requires the canonical integer, so you
pay a CPA every round.

**B6 — Multi-instance / BIP39 prefix.** Shared first-11-words only
shares a prefix of the *two setup* compressions. After 80 rounds the
midstates are uncorrelated. A breakthrough would be a related-chaining
value algorithm that evaluates `Compress(I,m)` and `Compress(I′,m′)`
in sub-2× work after a full avalanche — no such algorithm is known.

**B7 — Round-group / Mendel.** Rewriting the shift register as an
A-chain does not shrink `F`. A cheaper `F` *is* B4 at larger scale.

**B8 — Boolean / arithmetic minimization.** Ch/Maj are already one
LOP3. The nonlinear bulk is the 64-bit adders. An adder-free SHA-512
is a different function.

**B9 — Collective / change of basis.** Techniques that beat N× on
other maps need an inverse, a shared-base exp, a non-diagonal
bilinear tensor, a dense high-degree univariate, or joint dependence
on all N inputs. SHA-512 has none of those. Independent ANDs have
multiplicative complexity N. Mixing instances Fourier-style makes
Ch a convolution. See H23.

### What a GPU re-test would need

None of the search hits produced a new exact circuit. There is nothing
here for the RTX agent to time except the already-shipped HMAC-64 +
SHF path.

A future automated lead worth handing over: a program that computes
`Σ1(e)+Ch(e,f,g)` with two 64-bit rotates, passing `fused_spec_64` on
random triples **and** an SMT proof. That would be the 10% SHF
candidate.

### Failed approaches (do not reopen without new math)

- Closed form / homomorphism / addition-chain for `f^n` or `⊕ f^j`
- Fusing inner+outer into <160 rounds
- 2-round (or 4/8-round) algebraic cancellation
- Cross-round CSE of Σ/σ/Ch/Maj
- CSA or redundant / RNS / GF(2⁶⁴) state that stays exact *and* cheap
- Digit-slice as a better RTX machine than 32-bit SHF
- Deeper pad64 identities after `W[31]`
- Folding post-σ constants into `K[t]` (`σ` is not ℤ-linear)
- Nearby-mnemonic loop sharing; biclique on the U-chain
- Bitslice / warp-split bitslice
- Weight-2 Σ/σ; “trim W[8..15] saves 50%”
- Treating Choi BO, FPGA mega-rounds, or Mendel’s A-chain as op-count reductions
- Skipping HMAC iterations or changing `c` / the hash
- 2-rotate Σ (with or without a shift)
- Fusing Σ with Ch/Maj to drop a rotate (structured catalog + superopt)
- Sparse ADD+ROTR correction / joint ARX basis
- Cross-seed sharing of the 4094-loop after related BIP39 prefixes
- Work(N) < N·Work(1) by ≥10% via salt/bitslice/CLA/family/warp-circuit
- Work(N) < N·Work(1) by ≥10% via FFT/Walsh, multipoint, SWAR packing,
  mixed-instance ARX, batch-inversion analog, or other change of basis

## Batch complexity: is Work(N) < N · Work(1)?

Single-compression optimality is set aside. The question is whether a
**batch** of BIP39 candidates has a different dependency graph.

Every instance is a circuit `C(P_i, S)` with shared salt `S` and private
password `P_i`. A combinational circuit for `(C(P_1,S),…,C(P_N,S))` can
share a gate only if that gate’s inputs are in the shared cone
(functions of `S`, `K[t]`, IV, padding) **or** two private cones
accidentally compute the same value.

### Shared cone (proven, tiny)

| Shared node | Once per batch | Per-instance leftover |
|-------------|----------------|------------------------|
| SHA-512 `K[t]`, IV | yes | — |
| `pad(S \|\| 1)` and its 80-word `W` | yes (`u1_inner_block`; matches production U1) | 80 rounds on **different** `I_i` |
| `K[t]+W[t]` for that U1-inner block | yes | Σ/Ch/Maj/add on `I_i` |
| `"mnemonic"\|\|passphrase` PE | same as the U1-inner row | loop messages are `U_j`, not salt |

That is ≈ ¼ of **one** compression. Ratio `0.25 / (N·4098)`: **< 10⁻⁴**
for N=1, **< 10⁻⁷** for N=10⁴ (`shared_fraction_unrelated`).

U1 inner is the *only* loop-adjacent compression with a fixed message.
U1 outer’s message is the inner digest (private). Iterations 2..2048 have
private midstates **and** private messages.

### Related passwords do not merge the private cones

12-word mnemonics differing in the last word: first differing key word
is 8..11, so ipad and opad share that many rounds. Family of 128 valid
last words:

```
shared ≈ 0.25 + 2·prefix/80 compressions   (~0.5)
total  = 128 · 4098
ratio  < 10⁻⁵
```

Measured on `abandon…about` vs `abandon…legal`: I/O Hamming >180/512;
U1 Hamming >180; **0** equal words across 8 subsequent HMAC-64 steps
(`loop_word_collisions`). Unrelated passwords: same. 32 sequential
`seed-i` keys: I Hamming >160 between neighbors.

24-word passwords exceed 128 bytes, so `K'=SHA-512(P)`. A shared first
128-byte block saves one password-hash compression, still setup-only.

Avalanche after the first differing `W[t]` is why incremental HMAC of
the **loop** does not exist: `I` is a full 80-round mix of the whole
key.

### Bitslice / SIMD / prefix add / hybrid — work, not latency

Let `N=32` (one warp), one HMAC-64 compression.

| Organization | Add cost (batch of 32) | Rotate | Per-instance add vs 1120 IADD |
|--------------|------------------------|--------|-------------------------------|
| Word-parallel (current) | 32 × 80 × 7 × 2 IADD | 32 × 1550 SHF | **1120 IADD** (silicon CLA) |
| Bitslice, 32 instance-bits/reg | 80×7×64×3 = 107520 bitops | wire/SHFL | **3360 bitops** |
| Kogge-Stone software prefix | 80×7×(128+768) = 501760 | wire/SHFL | more than ripple |
| Transpose → bitslice Σ → transpose → IADD | 2×80×96 SHFL = 15360 | cheap Σ | **10× the SHF floor** |

Hardware `IADD` already *is* a carry-lookahead adder. Rebuilding it
across a batch, even with prefix techniques, **increases** total
operations. Prefix adders trade work for depth; throughput of N
independent adds wants minimum work, which is the ALU.

Wider-than-64 SIMD on RTX is the warp: 32 lanes × 32-bit. That is
already “one hash per lane,” not a single fused 1024-bit hash. Packing
two instances per thread is the old 2-wide path (same work, worse CPU
time).

A warp used as 32 bit-positions of **one** hash computes 1 instance per
32 lanes — 32× less throughput — to buy bitslice rotates and a software
adder. That is the losing layout.

### Lookup tables / generated Boolean networks

Ch/Maj are 3-bit → already 1 LOP3. A table of `I` for last-word indices
is 128 × 128 B of setup, then 128 independent 4094-loops. Four-Russians
helps a **fixed** linear map times many vectors; Σ is already 3 SHF and
is applied to different `e_i`. No amortization of the nonlinear 80-round
map: the domain is 512 bits.

### Conventional-DAG bound (H22 only)

`C_N(P_1,…,P_N; S) = (C(P_1,S), …, C(P_N,S))`.

In the *product of N scalar SHA-512 DAGs*, a gate is shareable only if
it is a function of `S` (and `K`, IV, padding) or two private cones
collide. That gives size `N · |private(C)| + |shared(S)|` with
`|shared| / |private| ≈ 0.25/4098`.

That is a statement about **common subexpressions in the conventional
basis**. It is not a statement about every algorithm for `C_N`.
FFT, batch inversion, fast multipoint evaluation, and Pippenger MSM
all compute many outputs cheaper than N scalar runs without those
outputs sharing the same scalar intermediates. The useful sharing is
in the *representation*.

## Change of basis: can Work(C_N) ≪ N · Work(C)?

The question is whether some other encoding of the N states makes the
*same* function cheaper. Tests live in `pbkdf2_basis` (9 new).
Bit-major / prefix-add (the one representation that is *not* a
rename of word-ARX) is measured in `arx_basis` and loses on RTX —
see “Blank-sheet basis” below. This section is the remaining space:
FFT, polynomials, packing, mixed SLPs, inversion analogs.
Production `derive` is unchanged.

### The phenomenon is real — on the wrong operation

Montgomery batch inversion: N inverses in `F_p` via one inverse and
`≤ 3N` muls. Measured: N=8 and N=32 beat N Fermat inversions, and the
recovered values satisfy `x·x⁻¹ = 1`.

The trick needs an **expensive abelian-group inverse** whose products
commute. SHA-512’s expensive ops are ADD / ROTR / Ch / Maj. There is
no inversion in the inner loop. Recasting a 64-bit word as a field
element and batch-inverting it computes a different function.

Pippenger / MSM is the same family: N independent `g^{a_i}` share a
group and a common base. HMAC-64 is `finalize(O_i, finalize(I_i, U))`
with a different key per password, not exponentiation.

### Which hooks beat N×, and why SHA-512 has none of them

| Hook | Why it beats N× | SHA-512 / PBKDF2 |
|------|-----------------|------------------|
| Group inverse (Montgomery) | 1 inv + O(N) muls | No inverse; ARX is already cheap |
| Same-base exp (Pippenger) | Bucket accumulation | Not `g^{a_i}` |
| Convolution / matmul | Tensor rank < N² | N independent products have rank N |
| Fast multipoint | Dense high-degree univariate | Gates are degree 2; no coeff vector |
| FFT of a *joint* map | Each output depends on all N inputs | Output *i* is independent of `P_j` |
| SWAR / under-filled word | 1 wide add = 2 narrow adds | RTX 32-bit ALUs are already full |
| Polarization of a quadratic | `f(x±y)` recover `f(x), f(y)` | HMAC / MiniSHA / MiniARX are not |

### Independent multiplications cannot be mixed (the algebraic barrier)

Ch = `z ⊕ (x ∧ (y⊕z))` is one AND per bit. N instances on disjoint
triples are N independent products.

**Exhaustive over GF(2):** no single AND of affine forms of `(a,b,c,d)`
has both `a∧b` and `c∧d` in the affine span of `{1,a,b,c,d,m}`. So two
disjoint ANDs require two multiplies even if the circuit may XOR the
four inputs together in any way. This is not a CSE argument: it is
multiplicative complexity in the algebraic circuit model, and it is
representation-independent *inside that model*.

The same-pair identity `a+b = (a⊕b) + 2(a∧b)` relates ADD and AND of
**one** pair. It does not produce a second pair’s AND.

The bilinear tensor of N independent products is diagonal and has
tensor rank N. Strassen-style decompositions do not apply.

### Linear change of basis makes the nonlinear part worse

Let `A` be any invertible linear mix of the N instance-states
(DFT, Walsh–Hadamard, `(x_0+x_1, x_0⊕x_1)`, …).

- ADD and XOR stay pointwise after paying `A` / `A⁻¹` (for DFT:
  `Θ(N log N)` extra). They do not become cheaper than N word-ops.
- Pointwise Ch in the Walsh domain is **not** Ch of the originals
  (60/60 random 8-lane batches). Correct evaluation is IFFT → Ch →
  FFT: `2 N log N + N·Ch` vs `N·Ch`.
- Circulant Σ is already 3-sparse. An FFT-N “diagonalization” is
  `2 N log N · 3` vs `3N` rotates (N=32: 96 vs > 4× that).

The cheap basis for sparse ARX **is** the standard word basis (H14
inside one instance; the same fact across instances). Mixing across
instances turns a pointwise low-degree map into a convolution.

A warp treated as one object is `I_32 ⊗ Round`. Evaluating that is
exactly 32 column-wise rounds. Packing 32 hashes into one
`GF(2³²)` element and applying a field op is a different function.

### No single ring makes a SHA round a cheap polynomial

- Over GF(2): Ch is degree 2 (Möbius on the 3-bit truth table).
  Wrapping-add is **not**: bit 3 of a 4-bit add has ANF degree ≥ 4
  because of carries.
- Over `ℤ/2⁶⁴ℤ`: XOR, Ch, and ROTR are not low-degree integer
  polynomials (ROTR is F₂-linear, not ℤ-linear).

Fast multipoint evaluation beats N Horner runs only for a **dense
high-degree univariate given by coefficients** (`d=N=256`: estimate
wins; `d=2, N=32`: Horner is already cheaper). SHA is a short
straight-line program of those mixed-algebra gates. Expanding 80
rounds to a monomial vector is larger than evaluating the circuit.

MiniARX-4 along an arithmetic progression of `x` does not have
vanishing 3rd or 7th finite differences, so even a *structured*
batch of states is not a low-degree integer curve after one ARX
step. Vanity passwords are not an arithmetic progression in
SHA-state space after `I`/`O` anyway.

### Packed representation / SWAR

Two 4-bit adds packed in 16 bits with a guard bit are exact (tested
on a grid). The pack/add/unpack sequence is **12 word-ops vs 2**
native adds. This wins only on a machine whose adder is wide and
whose bitwise ops are free. On RTX, `IADD` and `LOP3` have similar
throughput; the ALUs are already filled with 32-bit halves of
64-bit words. Bit complexity of N independent n-bit adds is
`Θ(N n)` in any case.

### Mixed-instance ARX does not factor

MiniARX-4 (`x' = x+rot₄(y,1)`, `y' = y ⊕ (x ∧ rot₄(y,2))`) is a
5-op SHA-like step. Two instances: 10 ops.

- Applying it to `(x_0+x_1, y_0+y_1)` is not the sum (or XOR) of
  the two images. MiniSHA-8 is not a homomorphism over `+` or `⊕`
  (80 random states). HMAC-64 fails `h(x)+h(y)=h(x+y)`,
  `h(x)⊕h(y)=h(x⊕y)`, and `2h(x)=h(2x)` (40 random keys/messages).
- Superopt: 8000 random straight-line programs of length 8–9 using
  ADD/XOR/AND/ROL on *any* mix of the four words, including
  cross-instance ops. **0** matched both outputs on 48+256 samples.
  A hit would have been a toy collective ARX win; there was none.

### Repeated HMAC is not a vectorized linear dynamical system

If we only needed `f^c(x)` and `f` were linear, matrix power would
help. PBKDF2 needs `T = ⊕_{j=1}^{c} f^j(x)` (all orbit points; a
linear toy already has orbit-sum ≠ last iterate), and `f` is a
different map per password (`I_i`, `O_i`). One warp is N different
recurrences, not one recurrence on a packed state.

### What this does *not* prove

A general Boolean-circuit theorem `Size(f^N) ≥ N Size(f) − o(N)` is
open (direct-sum / direct-product). Restriction of a mixed circuit
for `f^N` only yields `Size(f^N) ≥ Size(f)`, which is useless.

The claim is narrower and stronger than “the private cones are
disjoint”:

**Every known technique that evaluates N independent copies in
`o(N)` (or even `0.9 N`) times the scalar cost requires an
algebraic hook — expensive inverse, shared group exponent, bilinear
tensor of rank `< N`, dense high-degree univariate, or a function
that jointly depends on all N inputs. SHA-512’s costly operations
are already-optimal sparse ARX in the standard basis plus N
independent rank-1 products. Linear mixing across instances cannot
reduce the product count and turns the nonlinear map into a more
expensive convolution. There is no ring in which a round is a
low-degree polynomial worth multipoint evaluation.**

A future joint superoptimizer of 80-round SHA-512 on two instances
could in principle find a bizarre identity the MiniARX search
missed. That would have to evade the multiplicative-complexity
barrier on Ch/Maj/carries, which is the part that scales.

### What would reopen collective savings

A representation in which Ch/Maj/carry-AND of N disjoint triples
have multiplicative complexity `< N`, or a ring/basis where the
whole HMAC-64 map is a low-degree object with a fast multipoint
algorithm cheaper than N times the SLP, or a group encoding of
SHA state in which the round is a MSM-class operation. None of
those is supported by the tests above.

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

Ripple-carry is the wrong kill. The live question is whether a *different
basis* (bit-major + prefix add) beats word-major. That is `arx_basis` and
the section below. Short version: Kogge–Stone is what the ALU already is.

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

See the failed-approaches list under “Deeper exact-evaluation attacks.”
The SHF-specific items that stay closed: bitsliced SHA-512 on GPU as a
software basis (IADD already is the prefix adder), weight-2 Σ/σ, and any
claim of <2 SHF per 64-bit rotate on Ampere/Turing.

## Blank-sheet basis (MiniARX)

Question: if the job is millions of independent copies of this exact
function, is “64-bit words, 80 rounds, add, rotate” the cheapest basis,
or just the one everyone writes down?

The only representation that is actually *different* (not a rename of the
same ring operations) is **bit-major evaluation of the Boolean circuit**,
with addition as a prefix network over bit position. Everything else tried
from first principles collapses to that, or increases work:

| Invented basis | Mechanism | Kill |
|----------------|-----------|------|
| RNS / GF(2⁶⁴) / Gray / SD | hope add and rotate share a ring | SHA-512’s ops live in two incompatible structures (Z/2⁶⁴Z and GF(2)[x]/(x⁶⁴+1)). The second *is* the bit vector. Conversion at every op is extra work. |
| Hold CSA through the compression | rotate of (s,c) is free; 5:2 add is cheap | Ch/Maj need canonical bits of e,a every round. Resolving every round is a CPA. On an ALU, IADD ≈ LOP, so CSA+CPA > two IADDs (`csa3_issues`). |
| Orbit XOR of F = HMAC₆₄ | T = ⊕ F^j(U) as (I+F+…+F²⁰⁴⁷) | F is not linear over GF(2). Avalanche makes the nonlinear remainder the whole function. |
| Event-driven / BDD | skip gates that do not flip | Avalanche ≈ ½ the bits flip per round; BDD of 512-bit ARX is exponential. |
| Hybrid: bitslice only Σ/σ | rotate becomes a plane reindex | Must transpose to get there. 32×32 butterfly > 2 SHF (`hybrid_sigma` / word ≈ 5.4 on the GPU model). |

### The hypothesis that deserved a toy

Pack the batch so SIMD lane = **bit position of 32 hashes**, not **one
hash’s word**. Then:

1. **Representation.** A 64-bit word is 64 bit-planes. Plane `i` is a
   32-wide vector of bit `i` across the batch. Rotate is a rename / warp
   shuffle of planes. Add is Kogge–Stone over the 64 planes (6 stages),
   not 64-step ripple.
2. **What changes.** The carry dependence becomes a log-depth prefix.
   The 32 hashes share one issued gate. Rotates no longer touch SHF if
   planes live in named registers.
3. **What would be eliminated.** Not moved: the *word-level* rotate unit,
   and the carry logic already inside IADD (replaced by explicit prefix
   gates). That second replacement is the trap.
4. **Why it could beat word-parallel.** On a machine whose SIMD width is
   the *bit* batch (512-wide AVX-512, or an ASIC column per bit), one
   AND does 512 hashes and rotate is wiring. Word-parallel only packs
   `SIMD/64` hashes. Infinite-reg model: `ks_infinite / word ≈ 0.27`.
5. **Strongest objection.** A GPU warp IADD already performs 32 word-adds
   in one issue — it *is* a prefix adder in hardware. Re-emitting that
   network as SHFL+LOP is expanding a unit the ISA collapsed. Register
   files cannot hold `64 planes × 8 live words`.
6. **Toy.** `arx_basis`: 8-bit MiniARX, 8 hashes, 8 rounds, same coupling
   kinds. Word, bitslice-ripple, bitslice-KS, hybrid-Σ are bit-identical
   on 40 batches. Warp-issue totals: word 244, KS 1484, ripple 3388,
   hybrid 316.
7. **Full impl if it had survived.** NVIDIA: one warp = 32 bit-lanes of
   32 hashes, `shfl.sync` KS, stay bit-major for the whole HMAC. AVX-512:
   512 hashes × 64 ZMM planes — needs ~512 architectural registers (have
   32). That impl does not exist because (5) kills it.

Scaled HMAC-64 projection (`gpu_hmac64_cost(1.0)`, `wide_simd_hmac64_cost`):

| Machine | word | KS | ripple | hybrid Σ |
|---------|------|-----|--------|----------|
| GPU warp, SHFL=SHF | 2926 | 26830 (9.2×) | 287533 | 15814 (5.4×) |
| GPU, SHFL=0.25 SHF |  | still >2× word |  |  |
| AVX-512, 32 ZMM | 182.9 /hash | 3630 (spill) |  |  |
| AVX-512, ∞ regs | 182.9 /hash | **49.6** |  |  |

The 10–50%+ reduction exists only for a machine we do not have: **spatial
64-column datapath, rotate = metal, add = one CSA+CPA per round**. That
is how you would design the chip. On RTX / AVX-512 the word basis already
matches the ISA. Software cannot instantiate the wiring.

`cargo test -p erg-vanity-crypto --lib arx_basis`
