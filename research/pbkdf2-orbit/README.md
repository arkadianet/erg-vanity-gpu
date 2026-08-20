# Exact structure of the BIP39 PBKDF2-HMAC-SHA512 orbit

Author: arkadianet

This directory is a research harness. It does not change the production
PBKDF2 kernels. Nothing here is a candidate implementation until it
beats the conventional budget by a material exact-work margin **and**
matches an independent PBKDF2 test vector.

## Question

After HMAC ipad/opad precomputation, every BIP39 iteration is

```text
F(x) = Compress(O, pad64(Compress(I, pad64(x))))
```

with `|x| = 512` bits and `pad64` the unique SHA-512 padding of a
64-byte message. The derived key is not `F^2048(x)`. It is

```text
DK = F(x) ⊕ F²(x) ⊕ … ⊕ F²⁰⁴⁸(x)
```

The conventional algorithm evaluates `F` 2048 times (4096 SHA-512
compressions) and XORs as it goes. The question is whether this
specific envelope — fixed `I`, `O`, and padding, with the output of
one invocation becoming the exact 64-byte input of the next — has a
representation of `F^n` or of the orbit XOR that is substantially
cheaper than walking the orbit.

A 1–3% padding fold, a register reduction, or a better CUDA kernel
is out of scope.

## Conventional budget (full HMAC-SHA512, 2048 iterations)

Measured from the same round/schedule accounting used in the models
(`model.cost_F`, `model.conventional_budget`):

| quantity | value |
|---|---|
| `F` evaluations | 2048 |
| SHA compressions | 4096 |
| SHA rounds | 327 680 |
| word primitives (add/xor/and/not/rot/shr) | 11 976 704 |
| primitives per `F` | 5840 |
| sequential depth | 327 680 rounds |
| working memory | ~112 words |

The instrumented two-compression envelope matches `hashlib.hmac` and
the BIP39 `abandon…about` / empty-passphrase vector.

## Method

Models climb the brief’s ladder: toy → ARX → ARX+Ch/Maj → reduced SHA
→ reduced HMAC → full HMAC-SHA512 (sample tests). A toy win is only
kept if the same identity still holds after width and rounds increase.
A win that vanishes once the state exceeds the birthday scale
`2^{n/2}` is treated as insufficient diffusion.

Excluded on purpose (already studied elsewhere): CSE-only SHA
listings, ANF, Koopman linearization, Walsh, bitslicing, cycle
detection as an algorithm, ordinary exponentiation-by-squaring,
ordinary memoization, SIMD, conventional SHA micro-opts.

What was actually built and run (`python3 run_all.py`, ~25 s):

1. Pointwise identities (`F = id`, involution, `F(x)⊕x` constant,
   affinity over GF(2) and over `ℤ/2^{n}`, `DK = U1 ⊕ Un`, …).
2. Functional graphs on every enumerable domain (`n ≤ 16` bits):
   image size, cycle XOR sums, existence of a global coboundary
   `V(F(x)) = V(x) ⊕ x`.
3. Quadratic invariants over GF(2) (state-space factorization).
4. Word-flip homomorphisms (is word `i` of `F(x)` a function of
   word `i` only?).
5. Related-message scan of every matching `(phase, round, word)`
   between `F(x)` and `F(F(x))`, including full SHA-512 traces.
6. HMAC `I`/`O` coupling: real midstates vs random IVs.
7. Cone of influence from inner digest words into the outer
   compression.
8. Hash-consed word DAG of `F`, `F²`, `F⁴`, and `DK_n` with
   algebraic rewrites (const-fold, `x⊕x`, rot-over-xor, …).
9. Bit-blasted add (xor + carry chain) for the same compositions.
10. ROBDDs of `F^n` and `DK_n` on enumerable maps.
11. Berlekamp–Massey linear complexity of `n ↦ DK_n` (one bit).
12. Round-function semigroup generation on a 12-bit action.
13. Carry-save / folded-`I` exact-add accounting.

Raw output: [`results/latest.json`](results/latest.json).

## Results

No candidate produced a 10% exact-work reduction that survived the
ladder. The rest of this section is the tested record, not a
non-existence proof.

### 1. Telescoping the orbit XOR

If a function `V` satisfied `V(F(x)) = V(x) ⊕ x` for every `x`, then

```text
x ⊕ F(x) ⊕ … ⊕ F^{n-1}(x) = V(x) ⊕ V(F^n(x))
```

and `DK` would be two evaluations of `V` plus one `F^{2048}`. That
would remove the running XOR (negligible) but would **not** remove
the orbit unless `F^n` itself had a shortcut.

A global `V` exists if and only if every cycle of `F` has XOR-sum 0.

| model | bits | cycles | all cycle-XOR = 0 | coboundary |
|---|---|---|---|---|
| toy8 | 8 | 5 | no | no |
| toy12 | 12 | 10 | no | no |
| arx4x4r4 | 16 | 14 | no | no |

On the 16-bit ARX envelope `F` is a permutation (image fraction 1.0)
and still some cycles have nonzero XOR. The simple ansatzes
`V = id`, `V = F`, `DK = U1 ⊕ Un`, `DK = 0` for even `n` all fail
on every rung, including full SHA-512 samples.

So the “especially important” accumulation identity was tested. The
only exact doubling that holds for any `F` is the trivial one

```text
DK_{2m}(x) = DK_m(x) ⊕ DK_m(F^m(x))
```

which does not reduce the number of `F` evaluations unless `F^m` is
already cheaper.

### 2. Functional composition / envelope factorization

Word-level live DAG size after rewrites:

| model | `F` | `F²/F` | `DK_4 / 4F` |
|---|---|---|---|
| toy8 | 61 | 1.79 | 0.85 |
| toy12 | 103 | 1.85 | 0.90 |
| arx4x4r4 | 123 | 1.88 | 0.93 |
| ch8x4r8 | 382 | 1.93 | 0.96 |
| sha8x8r8 | 407 | 1.91 | 0.95 |
| sha16x8r16 | 807 | 1.94 | 0.96 |

The `DK_n / nF < 1` term is the ordinary orbit sharing (`F^k(x)` is
the input to `F^{k+1}`). It is the conventional algorithm, not a new
one. As soon as Ch/Maj and more rounds appear, both ratios climb
toward 2 and 1. Nothing like a factored `F = G ∘ H` with cheap
`G^n` showed up in the rewritten DAG.

Bit-blasting addition into xor+carry makes the composition *less*
sharable, not more: `F²/F` is 1.93–1.99 on every rung that fits.
Carries do not cancel across the HMAC seam.

### 3. State-space factorization

- Linear invariants that survive a hold-out: **0** on every rung.
- Quadratic invariants over GF(2), enumerable domains: only the
  constant (null dimension 1). No conserved coordinate.
- Per-word closure (flip another word, watch word `i` of `F`):
  **false** on every multi-word model, including full SHA-512.
- Image of `F`: ~0.45 on 8/12-bit toys (birthday), **1.0** on the
  16-bit ARX envelope. No factorization through a smaller set once
  the map is wide enough to be a permutation.

### 4. Cross-iteration / HMAC-envelope fusion

Matching-slot equalities between `F(x)` and `F(F(x))` at full
SHA-512 are exactly the first three rounds of the SHA shift
register still holding copies of the **IV**:

```text
s[0, {1,2,3,5,6,7}], s[1, {2,3,6,7}], s[2, {3,7}]
```

Those 12 slots equal `I` (inner) or `O` (outer) and therefore match
across iterates. They are not a relation between `x` and `F(x)`.
They die at round 4, when every original IV word has been
overwritten. They save no work: the IV is already free.

Seam “xor-constants” between `F`’s outer state and the next inner
state are `I_i ⊕ O_i`. Constant per password, useless across
iterations.

Real HMAC midstates (`K⊕ipad` vs `K⊕opad`, bytewise difference
`0x6a`) are **not** related by a key-independent xor or add. They
do not create extra pointwise identities that random `(I,O)` lack.

Outer round 0 uses only inner word 0. The other seven inner words
are unused for one round and then required for `W[16]` and for the
outer digest. All eight words of the inner digest also appear at
the same instant (Davies–Meyer at the end of the inner
compression). There is no delayed or implicit component that can
be skipped.

### 5. Iteration-closure representations

ROBDDs, enumerable maps:

- 8-bit and 12-bit: `F^n` and `DK_n` sit at the random-function
  BDD size (`~2^n / n`) for every `n`. The diagram does not shrink
  as `n` grows, so it is not a compact encoding of `F^n`.
- 16-bit ARX envelope: **one** real structure. After a single `F`,
  high-index words have small BDDs (word 3 bits: 261…1741 nodes
  vs ~8300 for a random 16-bit function). After `F²` every bit
  saturates at ~8300 nodes. `DK_2` is already saturated.

That one-`F` compactness is 4-round, 4-bit-word diffusion failure.
It does not survive a second envelope application, and it does not
survive 8-word / 16-round / 64-bit models. It is the kind of toy
win the brief asks to discard.

Berlekamp–Massey on `n ↦ (DK_n & 1)`:

| model | `n_max` | mean LC | random expect |
|---|---|---|---|
| toy8 | 128 | 9.5 | 64 |
| toy12 | 128 | 53.8 | 64 |
| arx4x4r4 and wider | 64–128 | ~`n_max/2` | `n_max/2` |

The only short recurrence in the iteration index is the 8-bit
orbit collapsing on a birthday scale. It is gone by 16 bits.

### 6. Alternative bases and semigroups

- Carry-save / folded `I` into the first 8 outer `K+W` adders:
  8 adds per `F`, **0.14%** of the full-SHA `F` budget. Does not
  scale with iteration count. Rejected as uninteresting.
- Residue / dual-rail / polynomial-ring encodings of rotate were
  not implemented as evaluators: every bitwise `σ` / Ch / Maj
  still requires a canonical word, so the redundant form has to
  be resolved before the next nonlinear step. That increases
  work, which fails the “only accept if it reduces exact work”
  rule.
- Round-function monoid on a 12-bit action, 16 generators:
  overflowed 4000 elements, no generator of small order, no
  collapse that would replace 80 products with a table.

### Required report card (best candidate: none)

| | conventional | best tested alternative |
|---|---|---|
| exact | yes | no cheaper exact algorithm survived |
| `F` evaluations | 2048 | 2048 (doubling still walks the orbit) |
| SHA compressions | 4096 | 4096 |
| primitive count | 11.98e6 | ≥ 11.98e6 − 8×2048 folded adds |
| sequential depth | 327680 rounds | same |
| memory | ~112 words | BDD / table forms are `Θ(2^{state})` |
| scales with iteration count | linear | no sublinear form found |
| survives width / rounds | n/a | every cheap-looking identity died |

## What this does *not* say

These are tested negatives for the hypotheses above, on the models
that were built. They are not a proof that no cheaper exact
algorithm exists. In particular the following were **not** closed:

- SAT / SMT superoptimization of a fused `F∘F` circuit at 8–12 bits
  with a human reading of any winning rewrite.
- Interpolation of reduced-round `F` over `GF(2^w)` as a univariate
  (the degree will explode; the question is whether a *special*
  reduced-round envelope is low-degree, which 4-round ARX already
  suggests it is not, given the permutation + saturated BDD).
- Tensor-network contraction orders for the 160-round envelope.
- A conjugacy `φ⁻¹ ∘ T ∘ φ = F` with `T` cheap to iterate, other
  than the ones implicitly ruled out by affinity / involution /
  low-order tests.

Production PBKDF2 is unchanged. If a later experiment produces an
identity that still holds on `sha64r20` and on sampled full
HMAC-SHA512, the next step is an independent test-vector check,
then and only then a prototype next to the current kernels.

## Run

```bash
python3 research/pbkdf2-orbit/run_all.py
```

No third-party packages. `model.py` is the ladder; `experiments.py`
is the hypothesis list; `symbolic.py` / `bdd.py` are the two
non-standard representations.
