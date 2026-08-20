# HMAC-envelope research log

Author: arkadianet

First-principles attack on the **actual** BIP39 PBKDF2-HMAC-SHA512 hot
loop. No external literature was consulted. Prior in-repo work
(`docs/pbkdf2_research.md` on `cursor/pbkdf2-hmac64-specialized-fbd7`,
and the orbit/algebra cycle) is treated as established evidence and is
not re-opened.

Code: `crates/erg-vanity-crypto/src/hmac_envelope.rs`.
Run: `cargo test -p erg-vanity-crypto hmac_envelope`.

## 1. Exact target

Vanity search, 24-word mnemonic, empty passphrase (GPU `vanity_seed`):

```text
K' = mnemonic bytes if |m| ≤ 128 else SHA-512(mnemonic)   // once
I  = Compress(IV, K' ⊕ ipad)                              // once
O  = Compress(IV, K' ⊕ opad)                              // once

U₁ = HMAC(K', "mnemonic" || INT32BE(1))                   // 12-byte msg
Uⱼ = F(O, F(I, Uⱼ₋₁))           j = 2..2048
T  = U₁ ⊕ U₂ ⊕ … ⊕ U₂₀₄₈                                // 64-byte seed
```

`F(H, m) = Compress(H, pad64(m))` with the **invariant** block

| Word | Value | Varies? |
|------|--------|---------|
| W[0..7] | `m` (8×64-bit BE) | yes |
| W[8] | `PAD = 0x8000000000000000` | no |
| W[9..14] | `0` | no |
| W[15] | `BITLEN = 1536` | no |

Per seed: **2 + 2 + 2047×2 = 4098** SHA-512 compressions. The 4094
HMAC-64 compressions dominate.

`T` is the BIP32 **message** (`HMAC-SHA512("Bitcoin seed", T)` in
`bip32.rs`). All 512 bits are consumed. Each `Uⱼ` is required both as
an XOR term and as the next HMAC input. No intermediate 512-bit state
can be dropped.

What generic SHA-512 analysis throws away, and what this computation
actually has:

- fixed `I`/`O` for 2047 iterates (already cached in the GPU kernel)
- identical `pad64` on **both** inner and outer, every iterate
- `input(n+1) = output(n)` in registers (`ulong8`), no byte codec
- W[8..15] compile-time constants; first expand is sparse
- the consumer is XOR-accumulation of the full chain, not a predicate
  on a prefix of the digest

## 2. Established evidence (not re-opened)

Orbit/cycle project: no useful folding, no re-entry, no memoisation,
iterates look random, maximal non-affinity, no GF(2) linearisation, no
orbit-sum, software bitslice loses, CSA/RNS/Gray/signed-digit/hybrid
Σ-bitslice fail.

HMAC-64 project (`pbkdf2_research.md`): H1–H21. First-expand
specialisation is ~3% work; midstate PE ~1.2%; 2-round fusion is the
same circuit; Σ has no 2-rotate form; inner+outer cannot become <160
rounds; CSA costs SHF; no closed form for `⊕ f^j`.

Those are accepted. This cycle asked a different question: does the
**envelope and the iteration boundary** still hide a ≥10% exact cut?

## 3. Categories

| ID | Claim | Cat | Result |
|----|--------|-----|--------|
| N1 | First-expand DAG has hidden CSE beyond 22σ | B | **Killed.** DAG = 23 add + 8 σ0 + 14 σ1. Independent recount matches the prior 22σ. |
| N2 | Schedule taint leaves some W[t] independent of some Mᵢ after W16 | A | **Killed.** W[16] depends on {M0,M1}; all eight message words have entered by W[23]; W[79] is full. |
| N3 | Inner and outer share a usable intermediate subgraph | A | **Killed.** Value-set intersection of one HMAC is <8 accidental 64-bit collisions. They share only `K[t]` and pad constants. |
| N4 | Digest words H1,H2,H3,H5,H6,H7 finalise before round 79, so the next HMAC can start early (≥10% overlap) | B/C | **Killed.** Ready rounds are [79,78,77,76,79,78,77,76]. Next **round 0** needs H0, which needs round 79. Overlap is 6×σ0 + W17 = 32 counted ops = **0.65%** of a specialised HMAC-64. |
| N5 | Absorb Davies–Meyer `I+E` into the next compression (iteration-boundary representation) | B | **Exact, useless.** Bit-identical. Saves 8 standalone adds if folded into T1; the prototype that still materialises the message is not faster. Release: absorb/generic = 0.97 (noise). Far below 10%. |
| N6 | After round 0, `a−e` is midstate-constant; this yields a cheaper round 1 | A | **Killed as a 10% path.** Identity holds (`round0_ae_delta`). Round 1 still needs Σ1(e), Σ0(e+Δ), Ch, Maj. Same 1.2% PE already recorded as H17. |
| N7 | MiniHMAC-8 is an XOR homomorphism, or `f⊕f²` is affine | A | **Killed.** 80/80 random pairs mismatch both tests (8-bit, 8 rounds). |
| N8 | Seven zero-W rounds are a simpler permutation (some src↛dst) | A | **Killed.** 8-bit: every src→dst pair influences across 200 samples. 64-bit: 20 random states × 8×8 pairs, **zero** independent pairs. You still pay 7 full ARX rounds; W=0 only drops the W-add (already in H3). |
| N9 | Superopt finds an 8-bit circuit for `Σ1+Ch` cheaper than cost 11 (3 ror + Ch + add) that could lift | A | **Killed.** 80k random programs, length 4–9, gate set {ror,shr,xor,and,add}. No cheaper match on the 64-sample filter. |
| N10 | `Σ1(x+y) = Σ1(x)⊕Σ1(y)⊕C` with C a 1-op form | A | **Killed.** 400 random 64-bit pairs: C never in {0,x,y,x⊕y,x∧y,x+y}. |
| N11 | HMAC-64 avalanche is incomplete, so some output bits can be delayed | A | **Killed.** 40 one-bit input flips: output Hamming 180–340 (≈256). |
| N12 | Adjacent iterates are close in Hamming, so a differential compressor wins | A | **Killed.** 32-step chain: U⊕HMAC(U) Hamming 180–340. |
| N13 | First-expand specialisation is a ≥10% cut | B | **Not new; confirmed ~3%.** Counted ops 5040 → 4892 per HMAC-64 = **2.94%**. First expand 208 → 134. Prior CPU measurement 3.2–3.5%. Below the bar. Not shipped (already on the other branch). |
| N14 | The 2048-XOR or BIP32 consumer allows dropping bits of U | A | **Killed by dataflow.** `T` is a 64-byte HMAC message; every `Uⱼ` feeds the next `F`. |

## 4. Kill ledger (full)

```text
Hypothesis: N1 first-expand hidden CSE
Why it might work: pad64 zeros might make two later W words share a σ
Required structural property: interned DAG σ-count < 22
Experiment: first_expand_dag hash-cons
Result: (add,σ0,σ1) = (23,8,14)
Exactness: exact (symbolic)
Instruction/work reduction: 0 beyond known 22σ
Memory/register cost: none
Measured speedup: n/a
Reason rejected: no extra CSE

Hypothesis: N4 iteration-boundary pipeline ≥10%
Why it might work: H1/H2/H3/H5/H6/H7 are known 1–3 rounds early
Required structural property: next compression's critical path can start
  before current round 79
Experiment: shift-register ready times + first-expand dependence on H0
Result: next round 0 needs W[0]=H0=O0+a79
Exactness: exact
Instruction/work reduction: 32 overlap ops / 4892 = 0.65%
Memory/register cost: a few extra live σ temporaries
Measured speedup: not implemented (work bound is 0.65%)
Reason rejected: producer/consumer dependency is the last `a`

Hypothesis: N5 DM-add absorption
Why it might work: next W[i] = mid[i] + working[i] is already a T1 addend
Required structural property: 8 adds disappear from the 10% budget
Experiment: encrypt_block + finalize_absorb_dm vs hmac64, bit-exact
Result: identical hashes; release ns ratio 0.97 (4000 HMAC-64)
Exactness: bit-exact (test absorb_dm_is_bit_exact)
Instruction/work reduction: ≤8 adds / ~2500 ops ≈ 0.3%
Memory/register cost: none if folded; extra if working is materialised
Measured speedup: none reliable
Reason rejected: representation win is real, size is 0.3%

Hypothesis: N7/N12 iterate algebra
Why it might work: T = ⊕ f^j(U1) might collapse if f or f⊕f² is linear
Required structural property: GF(2) homomorphism (or affinity of f⊕f²)
Experiment: MiniHMAC-8 homomorphism + 64-bit iterate Hamming
Result: 80/80 MiniHMAC mismatches; Hamming ~256
Exactness: exhaustive-on-samples / measured
Instruction/work reduction: none
Reason rejected: required property is false

Hypothesis: N9 cheaper Σ1+Ch
Why it might work: a 2-rotate fused form is the published 10% SHF path
Required structural property: equivalent circuit cost < 11 at 8-bit,
  then 64-bit lift
Experiment: 80k stochastic programs
Result: no cheaper match
Exactness: sampled; a miss is not a proof, but the cheap 2-rotate
  class was already exhaustively empty (prior H21)
Reason rejected: no candidate to lift

Hypothesis: N13 specialised first expand ≥10%
Why it might work: 11 σ + ~19 adds vanish from the first expand
Required structural property: that expand is a large fraction of HMAC
Experiment: op-count generic vs specialised (same 80 rounds)
Result: 2.94% of HMAC-64
Exactness: bit-exact (200 random blocks)
Reason rejected: real Category B, below 10%. Not a new discovery.
```

## 5. Benchmarks

Competent baseline = midstate-cached HMAC-64 with generic in-place
expand (the production GPU math, word-level).

| Quantity | Generic | Specialised first expand | Absorb-DM prototype |
|----------|---------|--------------------------|---------------------|
| Counted ops / HMAC-64 | 5040 | 4892 (−2.94%) | same math + 8 add/sub |
| First-expand ops | 208 | 134 | — |
| Boundary overlap ops | — | — | 32 (0.65%) |
| Debug ns / 4000 HMAC | 23.4 ms | — | 26.1 ms (1.12×) |
| Release ns / 4000 HMAC | 2.99 ms | — | 2.90 ms (0.97×) |

This machine: Intel Xeon (KVM), 4 cores, no GPU in the loop.
Release absorb/generic is **noise**, not a 10% cut. Instruction counts
are the honest signal.

No occupancy/SASS numbers: production kernels were not changed, and
this environment has no RTX device for an isolated PBKDF2 re-bench.

## 6. Why the envelope does not give 10%

Inner and outer are two sequential Davies–Meyer calls

```text
inner = E_{pad64(U)}(I) + I
U'    = E_{pad64(inner)}(O) + O
```

1. The only values shared across the pair are compile-time `K` and
   `pad64` constants. There is no common prefix/suffix of the 160-round
   graph once `I ≠ O` and `U ≠ inner`.
2. The iteration boundary is `U' →` next `pad64(U')`. Six of eight
   digest words are known 1–3 rounds early; the **first** word of the
   next message is not. SHA-512 round 0 of the next compression is
   blocked on the current last `a`.
3. `pad64` makes the first expand sparse. That is a real exact
   reduction (22σ instead of 32σ) and it is **~3%** of the HMAC, not
   ~10%. Later expands have no remaining zeros (taint is full by W23).
4. The XOR accumulator does not commute with the feed-forward add, and
   MiniHMAC is not a homomorphism, so the 2048-iterate XOR is not a
   cheaper functional graph than 2048 evaluations.

A ≥10% **exact** cut would require one of: a cheaper `F` (drop a
rotate from both Σ, or skip ≥8 of 80 rounds), a one-compression HMAC
(different function), or a closed form for `⊕ f^j` (break). None of
those survived contact with the 64-bit pad64 compressor.

## 7. Required findings

1. **Best surviving hypothesis.** N13 / prior H3: specialised first
   expand of `pad64` (22σ+~23add instead of 32σ+48add). Exact,
   ~3% work, Category B. Already derived on the other branch; this
   cycle independently recounted the DAG and the op budget.
2. **Strongest killed hypothesis.** N4: fine-grained pipeline across
   the iteration boundary. The shift-register geometry is real and
   was not in the prior kill list. It cannot start the next HMAC
   before the current last round. Overlap ceiling 0.65%.
3. **Largest exact work reduction discovered (this cycle).** 2.94%
   counted-op cut from first-expand specialisation (confirmation, not
   new). Largest **new** exact cut is N5’s 8 adds (~0.3%) or N4’s 32
   overlap ops (0.65%, ILP only).
4. **Largest measured real speedup.** None that survives a competent
   baseline. Release absorb/generic ≈ 0.97 on 4000 HMAC-64 (noise).
   No GPU delta.
5. **Most important structural insight.** HMAC-64 is two compressions
   glued by Davies–Meyer addition. The glue finalises `H0` only in
   round 79, so the producer/consumer relation does **not** unlock
   inter-HMAC fusion. The envelope’s only cheap structure is the
   sparse first expand, and that structure is a few percent.
6. **What remains genuinely unexplored.**
   - Exact synthesis of the 3-input 64-bit map `Σ1(e)+Ch(e,f,g)`
     outside the 2-rotate / 80k-program class (SMT on the 64-bit
     function; prior note still stands).
   - RTX SASS of an explicit first-expand kernel vs the current
     `SHA512_EXPAND16` (Category C; compiler may already fold
     `total_len=128`).
   - A cheaper `F` that is not a local rewrite of one round.
7. **Is another research cycle justified?** Only if it targets a
   **new** cheaper circuit for `Compress(H, pad64(m))` (SMT/synthesis
   of `Σ1+Ch`, or a multi-round `F` with a proof), or a GPU
   measurement of the already-known 3% expand. Another envelope or
   iteration-boundary cycle without a new algebraic property will
   re-derive the same 0.3–3% facts.

## 8. Outcome

**Negative result** on the ≥10% bar.

These structural properties were tested, these hypotheses were
derived, these experiments falsified them, and these specific classes
of shortcut therefore appear unavailable:

- inner/outer common subgraphs
- starting the next HMAC before the current last `a`
- DM-add absorption as a material cut
- MiniHMAC / iterate XOR algebra
- a cheaper local `Σ1+Ch` in the searched class
- delayed or partial digest words
- extra first-expand CSE

The pad64 first expand remains a true exact Category B reduction of
about **3%**. It is not a research breakthrough.
