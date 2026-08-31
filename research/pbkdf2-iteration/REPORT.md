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

### Experimentally unsuccessful (exact G2 synthesis, §9)

- Hash-cons of the definition circuit: `Cost(G2) = 2 Cost(F)` on every
  cost model, every tested key, and 2/3/4/8 rounds. Zero cross-iteration
  sharing.
- Per-output dead-code cones: each G2 bit uses essentially the F cone
  plus the F² cone (same AND count as the corresponding F² bit).
- Affine / EA identities relating G2 to F, F², or x: all false.
- `G2 = F ∘ g` for some g: impossible (`im(G2) ⊈ im(F)`).
- `H(x)=x⊕F(x)` is not cheaper than F (same degrees, same 4-var MC
  histogram, Walsh distances identical). `G2 = H∘F` is a tautology and
  does **not** recurse to a sublinear `G_{2048}`.
- 4-variable restrictions: G2 slices match F², not F. The apparent
  `MC(G2) < 2 MC(F)` on those slices is the 4-var cap `MC ≤ 3`, not a
  real saving.

### Theoretically plausible, not closed

- A SAT *lower* bound `MC(G2) ≥ 2 MC(F)` was **not** obtained. Degree
  gives `MC(G2) ≥ 7` and `MC(F) ≥ 5`. Constructive upper bounds are 92
  and 46 ANDs. The gap 7…92 is unclosed. 8-bit SAT at the degree
  bound timed out (neither SAT nor UNSAT).
- A cheap nonlinear conjugacy `ψ` of mini-HMAC to an affine map.
- Full 512-bit SHA-512. Nothing that survived on the reduced family
  justifies it.

### Not claimed

“SHA was designed to prevent shortcuts, therefore none exist.” That is
not used. The obstructions above are about associativity of composition,
degree of polynomial maps, and the failure of the ARX induction, each
either proven or measured on the reduced family.

---

## 8. Recommendation for the next experiment

Do **not** go to full SHA-512.

The G2 synthesis (§9) found no identity and no sharing. The only
remaining *exact* opening on this model is closing the SAT gap
`7 ≤ MC(G2) ≤ 92` with a better encoding (native XOR clauses, SAT
*upper* bounds at k=20–40 rather than at the degree minimum). If that
search produces a circuit with ≤ 80 ANDs, *then* extract the identity
and test recursion. Until a circuit strictly below `2 Cost(F)` is in
hand, further operator search on HMAC-like F is repeating a negative.

If someone still wants a dynamical-systems attempt: itinerary entropy
of the piecewise-affine (carry / Ch / Maj) decomposition along a
2048-step 64-bit orbit. Jacobian uniqueness already makes this unlikely.

---

## 9. Exact synthesis of G2 vs 2F (`minihmac_n4b2r4`)

Target: `w=8`, 4 words × 2 bits, 4 rounds, two compressions, seed 21.
`deg(F)=6`, `deg(F²)=deg(G2)=8`, Koopman 75, 0 linear invariants.

G2 was allowed arbitrary sharing. It was **not** forced to be two
copies of F. Cadical searched the complete AND-XOR model (each AND
takes two affine forms of earlier wires; outputs are affine forms of
all wires). The SAT harness was checked on `x0⊕x1` (MC=0) and
`x0x1x2x3` (MC=3, UNSAT at 2).

### 9.1 Constructive circuits (exact upper bounds)

Bit-level DAG of the definition, constant-folded I/O/pad, global
hash-cons, exhaustively equal to the integer F / F² / G2 on all 256
inputs.

| cost model | F | G2 (hash-cons) | two copies + 8 XOR | G2 / 2F |
|---|---|---|---|---|
| AND | 46 | 92 | 92 | **1.000** |
| XOR | 126 | 260 | 260 | 1.000 |
| NOT | 8 | 16 | 16 | 1.000 |
| ADD (2-bit) | 64 | 128 | 128 | 1.000 |
| ROT | 48 | 96 | 96 | 1.000 |
| all gates | 180 | 368 | 368 | 1.000 |
| weighted ARX (3A+2∧+⊕+…) | 466 | 940 | 940 | 1.000 |

Hash-cons saved **0** AND gates. The second F shares nothing with the
first except the 8 wires `F(x)`.

Dead-code cones (one output bit):

| bit | AND in F | AND in F² | AND in G2 |
|---|---|---|---|
| 0 | 36 | 82 | 82 |
| 1 | 45 | 91 | 91 |
| 2 | 26 | 72 | 72 |
| 4 | 22 | 68 | 68 |

Every G2 bit’s cone is the corresponding F² cone (F plus a full second
F, plus one XOR). DCE does not expose a cheaper G2.

Same 2× ratio for seeds `{21,22,99}` and rounds `{2,3,4,8}`:

```text
r=2  andF=4..8    andG2=8..16     ratio=1.000
r=3  andF=22..26  andG2=44..52    ratio=1.000
r=4  andF=46..50  andG2=92..100   ratio=1.000
r=8  andF=134..138 andG2=268..276 ratio=1.000
```

2-round F is under-mixed (few ANDs) and *still* has no G2 sharing.

### 9.2 Algebraic identities (exhaustive on the 256-point table)

| candidate | holds? |
|---|---|
| G2 = F, F², 0, id, F⊕id | no |
| G2 = M F ⊕ b (affine of F) | no |
| G2 = M F² ⊕ b | no |
| G2 = M F² ⊕ N x ⊕ b (EA of F²) | no |
| G2 = M F ⊕ N x ⊕ b | no |
| exists g with F∘g = G2 | no (`\|im F\|=110`, `\|im G2\|=89`, not a subset) |
| exists g with g∘F = G2 | **yes**, always: `g = H` on `im(F)` |

`G2(x) = H(F(x))` with `H(y)=y⊕F(y)` is an identity for every F, not a
discovery about HMAC. It gives `Cost(G2) ≤ Cost(F)+Cost(H)`. H has the
same algebraic degree as F (6), the same per-bit degree vector, the
same 4-var MC histogram, and Walsh distances within 0–8 of F. The
constructive circuit for H is F plus 8 XORs. So this rewrite is
`Cost(G2) ≤ 2 Cost(F) + 8`, i.e. the naive bound.

It does **not** compose to a sublinear `G_{2048}`:

```text
G4(x) = G2(x) ⊕ G2(F²(x)) = H(F(x)) ⊕ H(F³(x))
```

That is two H-evals at *different* odd iterates, which still requires
the even iterates of F. Memoized, it is 4 applications of F.

### 9.3 SAT multiplicative complexity

Model: k AND gates with affine inputs; 8 shared outputs. Complete for
Boolean maps. UNSAT at k would be a **proof** that every AND-XOR
circuit needs ≥ k+1 ANDs. Timeout is not a proof.

| map | deg | deg-lb on MC | SAT at k = deg−1 (20–30s) |
|---|---|---|---|
| F | 6 | 5 | timeout (vectorial and all 8 bits) |
| H | 6 | 5 | timeout |
| F² | 8 | 7 | timeout |
| G2 | 8 | 7 | timeout |

No circuit was found, and no k-UNSAT lower bound above `deg−1` was
obtained. Classification:

- **Not found:** an AND-XOR circuit for G2 with fewer than 92 ANDs.
- **Not proven:** that none exists. The proven AND lower bound is 7
  (degree). The proven upper bound is 92 (definition circuit).

Walsh / ANF (exact) already show G2 bits are not the cheap degree-8
functions (product of 8 affines ⊕ affine). Distance to the nearest
affine is 91–107 out of 256 (random-like). So MC = 7 is unlikely; the
solver timing out at k=7 is consistent with that, but is not UNSAT.

### 9.4 Exact synthesis on 4-variable restrictions

Every 4-var Boolean function has MC ≤ 3, so SAT **finishes**. 70
four-dimensional subspaces × 8 output bits = 560 restrictions per map.
A circuit for the 8-bit map restricts to a circuit for each slice, so
this is exact — but the 4-var cap makes `MC(G2) < 2 MC(F)` automatic
whenever `MC(F) ≥ 2`, and must not be read as a 8-bit win.

Histograms (560 restrictions):

| map | MC=0 | 1 | 2 | 3 | max over bits |
|---|---|---|---|---|---|
| F | 1 | 42 | 322 | 195 | 3,3,3,3,3,3,3,3 |
| H | 1 | 42 | 322 | 195 | same as F |
| F² | 0 | 6 | 293 | 261 | 3 everywhere |
| G2 | 0 | 15 | 287 | 258 | 3 everywhere |

G2’s histogram is F²’s, not F’s. Paired triples `(MC F, MC G2, MC F²)`:
the mode is `(2,2,2)` (179/560). G2 is cheaper than F² in 105/560
slices and *more expensive* in others (`(3,3,2)` occurs 93 times). No
systematic slice identity.

### 9.5 Synthesis verdict

On every cost model we could **evaluate** (AND, XOR, ADD, ROT, gates,
weighted ARX, per-bit cones, 4-var exact MC):

`Cost(G2) = 2 Cost(F)` (plus 8 XORs), with no surviving algebraic
rewrite that would cut that.

A 5–10% exact saving on this full-degree HMAC-like F was **not found**.
That is not a proof that a 80-AND circuit for G2 is impossible. It is
a proof that the definition circuit has no sharing, that the obvious
operator rewrites fail exhaustively, and that G2 behaves like F², not
like a simplified combination of two F’s.

---

## Verdict

Tried to disprove “2048 sequential HMACs are necessary.” Two exact
algorithms beat `n × F`, and both require structure HMAC-like F does
not have:

- F affine over GF(2) (or Q = F ⊕ F^{-1} affine) — `O(w^3 log n)`.
- Orbit shorter than n — `min(n, L)` evals; for a permutation,
  probability `n / 2^w`.

A third identity, new here, holds for every permutation including
real HMAC-SHA512: the orbit is exactly order-2 via `Q = F ⊕ F^{-1}`.
On every invertible SHA-like model Q is as hard as F, so the
recurrence does not reduce work.

I do not recommend changing the production PBKDF2 iteration loop.

---

## 10. New representations (not Koopman / Walsh / G2-SAT / ANF)

Scripts: `run_novel.py`, `run_quotients.py`, `run_invertible.py`,
`run_linstruct.py`, `run_algorithms.py`.
Log: `RESEARCH_LOG.md`. Raw: `results/{novel,quotients,invertible,linstruct,algorithms}.json`.

These are different objects from “unroll F and CSE.”

### 10.1 Order-2 recurrence of a permutation

HMAC-SHA512 of a 64-byte block is a permutation: each half is
Davies–Meyer around SHACAL-2, a permutation of the block. Reduced
Ch/Maj models lose that (hmac r4 has `|im F|=110`); two-key ARX
does not.

**Theorem.** If F is bijective and `Q = F ⊕ F^{-1}`, then

```text
F^{k+1}(x) ⊕ F^{k-1}(x) = Q(F^k(x))     for all x, k≥1.
```

So the orbit is an exact order-2 recurrence. `algorithms.gn_order2`
matches the naive XOR on linear F (`n≤2048`) and on arx-hmac r4
(`n≤256`).

This is cheaper than `n×F` if and only if one of the following holds.

1. `Cost(Q) < Cost(F)` as circuits.
2. Q is affine. Then `(u_k, u_{k-1})` is an affine map on `2w` bits
   and `G_n` is `O(w^3 log n)` — the same class as §1.1.

Measurements:

| model | deg F | deg Q | Q affine | interpolant nz F / Q | Cost(Q) as F⊕F^{-1} |
|---|---|---|---|---|---|
| linear (control) | 1 | 1 | **yes** | 9 / 9 | — |
| arx, 2–8 rounds | 7 | 7 | no | 253–255 / 251–254 | `2×F` |
| arx-hmac, 2–8 rounds | 7 | 7 | no | 251–253 / 253–254 | `2×F` |

Q is not a simpler map than F. The inverse ARX circuit has the same
primitive count as F. The identity is real and lives at SHA-512
width; it does not skip iterates and it does not shrink the circuit
unless someone finds a cheaper expression for `F ⊕ F^{-1}` than F
itself. On the 8-bit tables Q is information-theoretically dense
(≥251 of 256 monomials), so no such expression exists at this width.

### 10.2 Linear semiconjugacy tower

F is linearly conjugate to a T-function iff there is a flag of
linear forms such that the first `k+1` forms of `F(x)` are functions
of the first `k+1` forms of `x`. A single 1-bit linear quotient is
necessary.

The affine control has flag height 8 (full). Mini-HMAC r2 has height
3 (incomplete 2-bit diffusion). From **3 rounds** on, and on
invertible ARX-HMAC, the height is **0**. The same at 12-bit
(exhaustive) and 16-bit (4k random forms + structured masks).
This closes linear conjugacy to a T-function; bit-permutation
conjugacy was already closed in §4.

### 10.3 GF(256) interpolants, exceptional maps, sandwich

- Affine F: interpolant supported on Frobenius powers only.
  Mixed F: 245–256 nonzero terms. `G_n` is *denser*, not sparser.
- No deg-≤6 Abel function, no non-constant deg-≤4 Schröder function,
  no GF(256)-affine conjugacy onto `x²` / `x⊕c` / `x+c` / `μx` /
  `x^{2^k}` / rotation. Integer Abel of degree ≤2 over `Z/256`: none.
- `F^n = H_O ∘ Q^{n-1} ∘ H_I` holds. Q is not cheaper than F
  (same sparsity, degree, image, semiconjugacy height).
- MPO / unfolding ranks of F and `G_8` are full at the 16×16 cut.
- No commuting map in a library of XOR / add / odd-mul / rot /
  word-add except the identity.

### 10.4 Cycle prefix-XOR

`algorithms.gn_cycle_xor` is exact for every map (tested n=2048).
Cost is `min(n, p+L)` F-evals. For a **permutation** the cycle
through a random x is uniform in `1..2^w`, so

```text
P(orbit closes before n) = n / 2^w.
```

At `w=8` every orbit closes (`L≤256`); 5/5 starts used 21–68 evals
instead of 2048. At `w=16` and `w=32`, 0/5 starts closed before
2048. For BIP39, `2048 / 2^{512}`. The algorithm is the naive walk
plus an equality check that does not fire.

(Random *functions* have expected rho `Θ(2^{w/2})`. HMAC of a
64-byte block is a permutation, so the birthday figure does not
apply.)

### 10.5 Linear structures of `G_n`

A direction Δ with `H(x⊕Δ)⊕H(x)` constant. hmac r2 has 12
(under-mixed). From r=4, **F and `G_2, G_4, G_8, G_16, G_2048`
all have zero** linear structures, on both collapsed mini-HMAC and
bijective ARX-HMAC. XOR-of-iterates does not create a linear
structure that F lacked.

### 10.6 What is new, and what it is worth

The new exact object is §10.1: every permutation orbit satisfies a
canonical order-2 recurrence, and that recurrence is an `O(log n)`
algorithm **exactly when Q is affine**, which is when F is affine.
On every invertible SHA-like model, Q has the same degree and the
same interpolant density as F.

That is a classification, not a 10% circuit. Combined with the
complete linear-T-function test (§10.2) and the interpolant
measurement that `G_n` is denser than F (§10.3), the remaining
openings that are *not* “make one SHA-512 cheaper” are:

- a cheaper-than-F circuit for `Q = F ⊕ F^{-1}` at 512 bits
  (equivalent to a simplification of HMAC plus HMAC-inverse);
- a small-circuit Abel function that is not low-degree univariate
  and not GF(2)-linear (the cheap classes are closed);
- a SAT upper bound `MC(G2) < 92` from §9, still unclosed.

None of those is justified enough to touch production PBKDF2.
