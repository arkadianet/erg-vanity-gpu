# Exact algorithms for PBKDF2's XOR of HMAC iterates

Author: arkadianet

## Question

After HMAC ipad/opad midstates are precomputed, BIP39 PBKDF2-HMAC-SHA512 is

```text
U1 = F(P, S || INT(1))
U_{j+1} = F(P, U_j) = HMAC_P(U_j)
T      = U1 XOR U2 XOR ... XOR U2048
```

with

```text
F(x) = Compress(O, pad64(Compress(I, pad64(x))))
```

Is there an **exact** algorithm, bit-for-bit identical to PBKDF2, that needs
materially less work than 2048 applications of F?

A result counts only if it achieves one of:

- **A** — fewer F / HMAC evaluations
- **B** — fewer SHA-512 compression functions
- **C** — fewer primitive operations (ADD/XOR/AND/ROT/…)

A smaller-looking representation that costs as much or more to evaluate is
not a win.

This is not a GPU / SHA-512-implementation project. Production PBKDF2 was
not modified.

---

## 1. Strongest algorithmic ideas investigated

These are different from unrolling F and common-subexpression-eliminating
the circuit.

### 1.1 Affine semigroup / geometric series (control)

If `F(x) = A x ⊕ b` over GF(2), then `G_n(x) = XOR_{i=1}^n F^i(x)` is
itself affine. The pair `(F^k, G_k)` composes in the affine group, so
`G_n` is `O(w^3 log n)` word-XORs.

This is the classical reason XOR-of-`1..n` is `O(1)`: there `F(x)=x+1`.

### 1.2 Koopman operator as the object `R(F)`

The Koopman operator `U g = g ∘ F` is linear on the space of all functions
`{0,1}^w → {0,1}`. Coordinate functions of the iterates are
`U^k (x ↦ x_j)`. If those live in a `d`-dimensional `U`-invariant subspace
with `d << n`, then the iterate sequence (as **functions**) satisfies a
linear recurrence of order `d`, and `G_n` can be computed from the first
`d` iterates plus `O(d^2 log n)` linear algebra.

This is the reduced Koopman construction used for maps over finite fields
(Saha / Belur et al.): it is polynomial-size only for special low-degree
maps (certain FSRs), not for generic circuits.

### 1.3 Abel / Schröder conjugacy

If a cheap `ψ` exists with `ψ(F(x)) = ψ(x)+1` (or `λ ψ(x)`), then
`F^n = ψ^{-1} ∘ (ψ + n)` and `G_n` becomes an XOR of a cheap orbit in
the conjugated coordinate. Every permutation is conjugate to a translation
on each cycle; the question is whether `ψ` has a small circuit.

### 1.4 T-functions, 2-adic lifting, bit-permutation conjugacy

ARX addition is triangular in bit index (a T-function). If F were a
T-function, low bits of the orbit would close and Hensel-style lifting
could build `G_n` bit-slice by bit-slice. Rotations in SHA destroy this
unless a bit permutation (or similar conjugacy) restores triangularity.

### 1.5 Degree cancellation in the XOR

If `deg(F^{i+1}) > deg(F^i)` until saturation, the leading form of
`G_n` equals that of `F^n` — XOR cannot cancel the hardest term. After
degree saturates, `G_n` can in principle be simpler than `F^n`; we
measured whether that happens.

### 1.6 Derived operator `H(x) = x ⊕ F(x)`

`G_{2n}(x) = XOR_{i=0}^{n-1} H(Q^i(F(x)))` with `Q = F∘F`. A win
requires `H` (or `Q`) to be cheaper than F in a way that compounds.

### 1.7 Walsh / invariant linear forms / Jacobian

If F is close to linear in the Walsh basis, or preserves a cheap linear
partition, or has a constant GF(2) Jacobian (i.e. is affine), operator
powering becomes cheap. Measured, not assumed.

### 1.8 Semigroup doubling of the pair `(F^n, G_n)` at a single point

`G_{m+k}(x) = G_m(x) ⊕ G_k(F^m(x))` is an identity. Fast powering of
this pair as **functions** gives log-depth circuits of linear size.
Evaluating the same recurrence at **one** `x` without memoizing the orbit
uses **more** than `n` F-evals; with memoization it uses exactly `n`.

### 1.9 State-space exhaustion (table / ANF of `G_n`)

`G_n` as a function `{0,1}^w → {0,1}^w` has a circuit of size
`O(w 2^w)` independent of `n`. Building it costs `Θ(2^w)` F-evals per
password. This beats `n` F-evals only when `2^w ≲ n`.

### 1.10 Ideas deliberately not repeated

Register/occupancy/ILP, SASS, bitslicing, hash-consed Boolean DAGs,
semantic DAG merging, BDDs, ANF-as-the-algorithm, and
doubling-as-a-circuit-for-`G_n` were treated as already explored. Doubling
appears here only as an **equivalence check** and as a point-evaluation
cost argument, not as a proposed circuit optimization.

Known HMAC specializations (`4c → 2c+2` compressions, fixed padding,
first-round constants) are real **B/C** wins on a **single** F. They do
not reduce the number of iterates. They are out of scope.

---

## 2. Which ideas were genuinely different

| Idea | Different from circuit opt? | A/B/C target |
|---|---|---|
| Affine geometric series | Yes — closed form in a group | C, `O(log n)` |
| Reduced Koopman | Yes — operator on function space | A if `d << n` |
| Abel/Schröder conjugacy | Yes — change of coordinates | A/C if `ψ` is cheap |
| T-function / 2-adic lift | Yes — dynamical structure of ARX | C if it closes |
| Degree cancellation | Yes — algebraic identity for the XOR | C if leading terms die |
| `H = id ⊕ F` rewrite | Yes — operator transform | C if H is simpler |
| Walsh / linear invariants | Yes — invariant discovery | A if a cheap quotient exists |
| Pair doubling at a point | Yes — semigroup algorithm | A (fails; see §6) |
| Full-table `G_n` | Yes — but `2^w` preprocessing | A only if `2^w ≲ n` |

---

## 3. Experiments and equivalence tests

Hierarchy (all maps `{0,1}^w → {0,1}^w`):

1. Affine over GF(2)
2. Sparse quadratic
3. Tiny add/shift/xor recurrence
4. Pure ARX
5. ARX + Ch + Maj
6. Reduced SHA-512 compression (Davies–Meyer, HMAC-like padding)
7. Mini-HMAC: `F(x) = Compress(O, pad(Compress(I, pad(x))))`
8. Same mini-HMAC at 32- and 64-bit state for single-orbit tests
   (`n` up to 2048). Full 512-bit SHA-512 was not run: nothing
   that survived steps 5–7 had a reason to scale.

Reproducible via `python3 research/pbkdf2-iteration/run_experiments.py`.
Raw numbers: `research/pbkdf2-iteration/results/experiments.json`.

Exactness checks that all passed:

- Affine closed form vs naive `G_n` for `n ∈ {2,…,2048}` on `w=8` and `w=16`.
- Functional-graph doubling vs naive `G_n` on every table-sized model.
- Mini-HMAC even-`n` identities: `G_2 ≠ 0`, `G_2 ≠ F`, `G_4 ≠ G_2`.

Cost model: each ADD/XOR/AND/NOT/ROT/SHR in the model definition is one
primitive. Baseline is `n × cost(F)` for `n = 2, 4, …` as far as the
method allows.

---

## 4. Cost / growth measurements

### 4.1 The control works (so the harness can see a real win)

Affine `F` on 16 bits, `G_n` closed form vs naive primitives:

| n | equivalent | closed / naive |
|---|---|---|
| 2 | yes | 171 |
| 64 | yes | 11.5 |
| 256 | yes | 3.69 |
| 1024 | yes | 1.13 |
| 2048 | yes | **0.62** |

At BIP39's `n=2048` this is a genuine **C** win, of the kind the question
is about. It exists because F is affine, not because XOR-of-iterates is
generically easy.

Koopman rank for the same map saturates at `w+1 = 9`. Walsh support is 1.
Jacobian is constant. Linear complexity of an orbit is `O(w)` and the
connection polynomial is independent of the start point.

### 4.2 Pair doubling does not reduce F-evals at a point

| n | F-evals, recursive doubling, no memo | F-evals with orbit memo |
|---|---|---|
| 16 | 48 | 16 |
| 256 | 1280 | 256 |
| 2048 | 13312 | 2048 |

Memoized doubling **is** the sequential walk. This is an identity, not a
measurement.

### 4.3 SHA-like models: no A/B/C win

Once the model is HMAC-like with enough rounds for mixing, every
operator-level statistic matches a generic function:

| model | w | aff | T-fn | deg F | deg `G_n` | cancel | Koopman | Walsh / 2^w |
|---|---|---|---|---|---|---|---|---|
| linear | 8 | yes | yes | 1 | 0 at large n | yes | 8→9 | 1/256 |
| quadratic | 8 | no | no | 2 | = deg `F^n` | no | 8→73, still rising | sparse |
| tiny NLR | 8 | no | no | 6 | = | no | 8→68, saturates | 16/256 |
| ARX 4×2, 4r | 8 | no | no | 7 | = | no | 8→136 (cap) | 227/256 |
| mini-HMAC 4×2, 2r | 8 | no | no | 3 | = | no | 8→17 | 3/256 |
| mini-HMAC 4×2, 4r | 8 | no | no | 6 | 8 | no | 8→75 | 158/256 |
| mini-HMAC 4×3, 4r | 12 | no | no | 10 | 12 | no | 12→108 (cap) | 2524/4096 |
| mini-HMAC 4×4, 4r | 16 | no | no | 15 | 16 | no | 16→80 (cap, +16/step) | 56k/65k |
| mini-HMAC 8×2, 8r | 16 | no | no | 15 | 15 | no | 16→80 (cap, +16/step) | 64k/65k |

`H(x)=x⊕F(x)` never dropped the degree and never became affine for any
non-affine model. ANF(`G_2`) was never materially smaller than ANF(`F²`);
for the 16-bit 8-round HMAC it is 524288 terms — one monomial per
input/output bit — i.e. information-theoretically dense.

Bit-permutation search never turned a non-T-function into a T-function.

Invariant linear forms: 7–15 on **under-mixed** 2-round maps, **zero**
as soon as the model has 3–4 rounds.

Single-orbit tests on 32- and 64-bit mini-HMAC (`n=2048`):

- Primitive count is exactly `n × cost(F)` (ratio 1.000).
- Linear complexity of 512 iterates, per output bit: **255–258**.
  For a length-512 GF(2) sequence the maximum is 256. The bits are
  LFSR-indistinguishable from random.
- Connection polynomials differ across start points (no key-independent
  recurrence to precompute).
- 24 successive GF(2) Jacobians along an orbit: 24 distinct.
- Low-`k`-bit truncation already disagrees at `k=1` (rotations feed high
  bits into low bits on the first evaluation).
- `G_16 ≠ 0`. Even `n` does not cancel HMAC-like iterates.

### 4.4 The only “structure” is incomplete mixing, and it dies

Follow-up on 4-word mini-HMAC, varying rounds and word width:

| rounds | bits | deg F | Koopman last | linear invariants | Walsh mean / 2^w |
|---|---|---|---|---|---|
| 1 | 2 | 1 | 9 | 66 | 1 / 256 |
| 2 | 2 | 3 | 17 | 7 | 3 / 256 |
| 3 | 2 | 5 | 64 | 0 | 22 / 256 |
| 4 | 2 | 6 | 63 | 0 | 154 / 256 |
| 6 | 2 | 8 | — | 0 | 239 / 256 |
| 2 | 3 | 5 | 61 | 15 | 10 / 4096 |
| 3 | 3 | 7 | 100 | 0 | 186 / 4096 |
| 4 | 3 | 10 | cap | 0 | 2508 / 4096 |
| 2 | 4 | 6 | 57 | n/a | 53 / 65536 |
| 3 | 4 | 11 | cap | n/a | 2422 / 65536 |
| 4 | 4 | 15 | cap (+w/step) | n/a | 56184 / 65536 |

One- and two-round 2-bit HMAC is a low-degree map with a small Koopman
space. That is not an algorithm for PBKDF2. It is a 2-bit, 2-round hash
that has not avalanched. Three rounds wipe the linear invariants. Four
rounds on 4-bit words already give near-max degree and a Walsh spectrum
that is 86% dense. Eight-round 8-word 2-bit HMAC is 97% dense and a
permutation with a 56k-cycle — still no cheap Abel function.

No 5–10% exact primitive saving appeared on any model that still had
Ch/Maj, ARX, two-compress HMAC structure, **and** enough rounds to mix.

---

## 5. Strongest surviving hypothesis

**There is no exact sublinear (in n) algorithm for `G_n(x)` when F is
password-dependent HMAC-SHA512-like.**

More precisely: every operator `R` we could attach to F that *does*
power cheaply (matrices, Koopman on a small invariant space, T-function
slices, Walsh spikes, affine Jacobians, Abel labels) is small only when
F is affine or has not mixed. As soon as the reduced model is SHA-like
enough to have near-maximal algebraic degree, those objects become
`Θ(2^w)`-sized or orbit-sized, which for `w=512`, `n=2048` is worse than
walking 2048 steps.

The conventional algorithm — precompute I/O, then apply the two-compress
F 2048 times and XOR — remains the exact algorithm.

A 10%+ win, if one exists at all, is still in the already-explored
category “make one F cheaper” (fixed pad, fixed I/O, first-round
constants), not “skip iterates.”

---

## 6. Strongest mathematical obstruction

Three separate obstructions, none of which is “SHA is nonlinear.”

### 6.1 Point evaluation of an associative operator is not free

Function composition is associative, so `F^{2k} = (F^k) ∘ (F^k)` and

```text
G_{m+k}(x) = G_m(x) ⊕ G_k(F^m(x))
```

in `O(1)` after you have `F^m(x)` and the two G-values. Getting
`F^m(x)` for a generic circuit F is itself `m` evaluations. Memoizing
the orbit makes the doubling recurrence use exactly `n` evaluations of
F. This is **proven** for black-box / straight-line evaluation at a
single x. It is why exponentiation-by-squaring does not reduce **size**
or **point cost** for a nonlinear map given as a circuit.

Koopman geometric series `U + U^2 + … + U^n` is the same identity in
operator language. Over GF(2),
`(I+U)^{2^k} g = g ⊕ g ∘ F^{2^k}`, which still requires `F^{2^k}`.

### 6.2 Small Koopman spaces exist only for low-degree F

The space of functions of algebraic degree `≤ d` is `U`-invariant iff
`deg(F) ≤ 1`. Coordinate functions of a degree-`δ` map generate a Krylov
space whose dimension grows until it hits `min(n w, w 2^w)` unless F is
(piecewise) affine. That is a theorem about polynomial maps, not a SHA
slogan. The measurements in §4 are the finite-width instance: rank
increases by `w` per iterate (new coordinate functions independent of
all previous ones) as soon as mixing is sufficient.

Building the reduced Koopman matrix, when it is not already small,
costs `Θ(2^w)` F-evals **per password**, because I and O depend on P.
There is no amortization across BIP39 candidates.

### 6.3 SHA's rotations kill the only cheap ARX induction

A T-function / 2-adic lift would be a real C algorithm. One rotate
makes bit 0 of F(x) depend on high input bits. Empirically the 1-bit
truncation already fails. Lifting `F^n` from `mod 2^k` to `mod 2^{k+1}`
then needs the Jacobian **along the whole orbit** (chain rule), i.e.
the orbit itself.

Conjugacy to a T-function by a bit permutation was searched on every
table-sized model and not found.

---

## 7. Proven / unsuccessful / untested

### Proven (for the evaluation model that matters)

- Black-box / orbit-memoized evaluation of `G_n(x)` uses `n` F-evals.
  You cannot skip an iterate without an identity that relates `F^{k+1}(x)`
  to earlier values **without applying F**.
- Affine F has an `O(w^3 log n)` exact algorithm. We implemented it and
  matched the naive XOR bit-for-bit.
- `G_n` as a lookup table is `O(2^w)` per key and wins only for
  `2^w ≲ n`. For BIP39, `2^{512} ≫ 2048`.

### Experimentally unsuccessful (on every SHA-like reduced model)

- Reduced Koopman dimension `≪ n`
- Degree cancellation in `G_n`
- `H = id ⊕ F` simpler than F
- Constant Jacobian / affine conjugacy
- T-function, bit-permutation conjugacy to a T-function
- 2-adic closure of low bits
- Invariant linear forms (vanish by 3–4 rounds)
- Sparse Walsh spectrum (densifies with rounds)
- Key-independent short LFSR on the iterate bits
- Even-`n` XOR collapse from Davies–Meyer `+ O`
- Pair doubling as a point algorithm

None of these is a proof that no other `R(F)` exists.

### Theoretically plausible, not tested here

- SAT / exact Boolean synthesis of the **minimum** circuit for `G_2`
  versus `2F` on the smallest **full-degree** mini-HMAC
  (`minihmac_n4b2r4`, w=8, deg 8, Koopman 75). Existence of a smaller
  circuit is not ruled out by ANF size or by “we did not find CSE.”
- Search for a **small non-linear** conjugacy `ψ` (not a bit permutation)
  of mini-HMAC to an affine map or a monomial. Existence of some `ψ` is
  guaranteed on each cycle of a permutation; existence of a **cheap** `ψ`
  is the open statement.
- A lower bound that reduced-Koopman dimension is
  `Ω(min(n w, 2^{c·(# nonlinear gates affecting the carried state)}))`
  for this specific circuit family.
- Full 512-bit SHA-512. Not justified by anything that survived.

### Not claimed

“SHA was designed to prevent shortcuts, therefore none exist.” That is
not used. The obstructions above are about associativity of composition,
degree of polynomial maps, and the failure of the ARX induction, each
either proven or measured on the reduced family.

---

## 8. Recommendation for the next experiment

Do **not** go to full SHA-512. Do **not** re-expand `G_n` as a DAG.

Run exact circuit synthesis on the smallest HMAC-like F that has already
lost every cheap invariant:

```text
minihmac_n4b2r4     # 4 words × 2 bits, 4 rounds, two compressions
w = 8
deg(F) = 6, deg(F²) = 8
Koopman rank 75 (saturated)
0 linear invariants
Walsh already filling
```

Question: is `size*(G_2) < 2 size*(F)` for a minimum (or SAT-bounded)
AND/XOR circuit, by even 5–10%?

- If **no** (min circuit of `G_2` is essentially two copies of F plus 8
  XORs): that is evidence, at the first full-degree HMAC-like map, that
  the XOR-of-two-iterates problem has no extra algebraic identity. Stop
  the operator search.
- If **yes**: that identity is the object `R(F)`. Scale immediately to
  `n=4,8` and to `b=3`, `nwords=8`, and see whether the gap is a
  2-bit accident or a real composition law.

A secondary, cheaper experiment: treat one SHACAL-like round as a
piecewise-affine map (carries + Ch/Maj choice bits) and count the
itinerary entropy along a 2048-step 64-bit mini-HMAC orbit. If the
symbolic itinerary is compressible, variation-of-constants on the linear
pieces might beat `n F`. The Jacobian uniqueness in §4.3 already makes
this unlikely; it is the last standard “nonlinear = piecewise linear”
attack that was not fully costed.

---

## Verdict

Tried to disprove “2048 sequential HMACs are necessary.” The only exact
algorithm that beat `n × F` was the one that applies when F is affine.
Every HMAC-like model that mixed like SHA-512 lost that structure, and
the reasons it lost it are operator-level, not “the circuit was not
optimized hard enough.”

I do not recommend changing the production PBKDF2 iteration count or
replacing the loop with a different exact recurrence.
