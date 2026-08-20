# Orbit-XOR algorithms for iterated HMAC

Author: arkadianet

Given a password-parameterized map `F` and a start `U`, the BIP39 PBKDF2
block is

```
U_1 = F(P, S)
U_{j+1} = F(P, U_j)
T     = U_1 ⊕ U_2 ⊕ … ⊕ U_2048
```

The usual algorithm walks the orbit. That is not a theorem. This note
asks whether `T` can be obtained by a different algorithm, using only
the shape of that recurrence.

Production derive is not touched. The toy lives in `orbit_xor`.

## The object that is not the walk

Write `Y_k(x) = F(x) ⊕ F²(x) ⊕ … ⊕ F^{2^k}(x)`.
Then `T` is `Y_11` (up to a shift of the start). The doubling law

```
Y_{k+1}(x) = Y_k(x) ⊕ Y_k(F^{2^k}(x))
```

is an identity for every `F`. It does not by itself save work: you still
touch `2^{k+1}` orbit points unless `Y_k` has a cheaper representation
than “walk `2^k` steps.”

**Algorithm (polynomial doubling).** Represent `F` as a vector of
polynomials over GF(2). Compose and add in that ring:

```
Y_0     = F
Y_{k+1} = Y_k + Y_k ∘ F^{2^k}
```

Eleven steps produce `T` as a polynomial. Evaluate it at `U`.
This beats `2048` applications of `F` exactly when the polynomials stay
smaller than `2^k |F|`.

That is the unreasonable idea. It is true for some `F` and false for
others. The rest is which class HMAC belongs to.

## Calibration (the idea works)

`F(x) = rot(x,1) ⊕ 0x1d` is affine over GF(2). Every `Y_k` is affine
(degree 1, ≤ 9 monomials). Eight iterates cost one XOR-rotate, not eight.

So the algorithm is not vacuous. The required property is: `F` is a
low-degree, sparse polynomial map (or linearly conjugate to one).

## HMAC-shaped toys

`F` is two Davies–Meyer layers with key-derived `I,O`, the same nesting
as HMAC, on 8- and 16-bit words. “Rounds” means ARX steps inside the
compress, not SHA-512 rounds.

### 1-round — the collapse

8-bit, key `0x41`:

| map | max ANF weight | degree |
|-----|----------------|--------|
| `F` | 16 | 5 |
| `Y_3` (8 terms) | 12 | 3 |
| `Y_4` (16 terms) | 2 | 1 |
| `Y_5` (32 terms) | 0 | 0 |

`Y_5` is the zero function: the XOR of 32 iterates is `0` for every
start. Max cycle length ≤ 32, so this is partly the functional graph
wrapping inside a dyadic window.

16-bit, key `0x4141` (image only 256, but 16 input bits):

| map | max ANF weight | degree |
|-----|----------------|--------|
| `F` | 15 | 6 |
| `Y_3` | 23 | 5 |
| `Y_4` | 15 | 4 |

Degree falls as the block doubles. `Y_4` is a 15-term degree-4
polynomial. Evaluating that polynomial is about one `F`, not sixteen.
This is a genuine cheaper algorithm for this `F`.

### 2-round — the collapse dies

16-bit, two ARX steps per compress:

| map | max ANF weight | degree | image |
|-----|----------------|--------|-------|
| `F` | 25529 | 16 | 5066 |
| `Y_3` | 25661 | 16 | — |

`F` is already a dense function of all 16 bits. `Y_3` does not shrink.
Polynomial doubling is just a worse encoding of the truth table.
Three rounds is the same: degree 16, weight > 10⁴.

8-bit two-round maps fall into a 2-cycle (`… → 0x96 → 0xf4 → 0x96`).
Linear complexity of an orbit bit is tiny. That is a domain-size
artifact, not a 512-bit algorithm.

## Other doors, closed on the toy

- `F(x ⊕ F(x)) = F(x) ⊕ F²(x)` never holds (rate 0). `(id ⊕ F)` as a
  composed operator is not the orbit XOR.
- `T` is not `x ⊕ F^c(x)`, not `F^c(x)`, not `x` (≤ a few accidental
  hits in 256 starts).
- `T(P)` as a function of the password is not simpler than `U_1(P)`.
- Walsh spectrum of a 2-round output bit is dense (≥ 128 / 256).
- 400 random linear conjugacies `A⁻¹ F A`: none affine.
- 2-round `F` is not affine, not quadratic (second difference not
  constant), image size is not a power of two (not conjugate to any
  affine map).

A black-box `F` still needs `c−1` evaluations to produce `c` orbit
points. Every cheaper algorithm has to open `F` or replace `Y_k` by
something smaller. Opening `F` as a polynomial only helps while that
polynomial is sparse and low-degree.

## What this says about the 2048-step HMAC

One HMAC-SHA512 of a 64-byte string is two 80-round compressions.
Algebraic degree of an ARX compress crosses the 512-bit cap after a
handful of rounds (each Ch/Maj/carry AND can double degree). After
that, `F` is a dense element of the 512-bit function algebra, in the
same regime as the 16-bit 2-round toy, not the 1-round toy.

Polynomial doubling then produces `Y_11` of size `Θ(2048 |F|)`, which
is the walk. The doubling law remains true and useless.

The 1-round algorithm does not lift by “using bigger words.” It lifts
only if someone writes HMAC-SHA512 as a sparse low-degree polynomial
in a basis we do not have.

## Factored circuits, not expanded ANF

Dense ANF does not imply a large circuit. `G_n` is built here as a
hash-consed bit DAG (XOR/AND with algebraic rewrite: `a⊕a=0`,
`a∧a=a`, const-fold, commuted keys) plus **semantic CSE**: two nodes
that compute the same Boolean function of `x` collapse, even if they
were built by different syntax.

The pair is constructed both sequentially and by doubling

```
F^{2n} = F^n ∘ F^n
G_{2n}(x) = G_n(x) ⊕ G_n(F^n(x))
```

I,O midstates and `K[t]` are constants and fold. Rotates are rewires
(free). What remains is Ch/Maj/carry AND and the XORs of adders.

`orbit_circuit` is the implementation. Circuits are checked against
the scalar `hmac_f` / `hmac_f16`.

### Measured growth (best CSE of the unrolling)

**Affine `F(x)=rot(x,1)⊕0x1d`.** Zero ANDs. Semantic nodes stay < 100
out to `G_16`. The compact representation exists.

**1-round 8-bit HMAC, key `0x41`.** `G_32` is the zero *function*
(BDD size 2). The unrolled cone is still 2759 syntactic / 332
semantic nodes — the walk is still in the DAG, the output map is
not. Best representation of `T` is “emit 0.”

**2-round 8-bit HMAC** (max cycle 2 — wrap artifact):

| n | syn / F | sem / F | AND / F | BDD(G) |
|---|---------|---------|---------|--------|
| 1 | 1.00 | 1.00 | 1.00 | 266 |
| 2 | 1.99 | 1.97 | 1.98 | 307 |
| 4 | 3.98 | 3.83 | 3.83 | 301 |
| 8 | 7.95 | 5.73 | 5.87 | 297 |
| 16 | 15.89 | 5.86 | 6.18 | 298 |

Syntactic size is `n |F|`. Semantic size flattens only after the
2-cycle. BDD(`G_n`) is ~300 for every `n` because every 8-bit map
has a small BDD. That does not lift to 512 bits.

**16-bit HMAC, 2 rounds** (image 5066, max cycle 9):

| n | syn / F | sem / F | AND / F |
|---|---------|---------|---------|
| 1 | 1.00 | 1.00 | 1.00 |
| 2 | 2.00 | 1.99 | 1.99 |
| 4 | 3.99 | 3.96 | 3.96 |
| 8 | 7.97 | 7.57 | 7.70 |

`F` is 1024 syntactic nodes, 370 ANDs. Through `n = 4` (below the
cycle length) every factored metric is `n × |F|` to two percent.
`G_8` dips only because 8 ≈ cycle 9.

**16-bit HMAC, 3 rounds** (image 17343, max cycle 14):
`sem(G_2)/sem(F) = 2.00`, `sem(G_4)/sem(F) = 3.99`.

**4×4-bit “SHA” toy** looked like `sem(G_8)/sem(F) = 2.86`. Its
image is 11 and max cycle is 1. Flattening was wrapping, not
sharing. Discarded as a mixing model.

Doubling and sequential hash-cons to the **same** DAG size. The two
copies `G_n(x)` and `G_n(F^n(x))` share constants only:
`sem_AND(G_2) ≈ 2 · sem_AND(F)` (176 vs 89 on 8-bit 2-round).

### What the curve says

While `n` is below the functional-graph cycle length, the best
factored circuit we can extract from the unrolling — syntactic CSE,
semantic CSE, AND-count, doubling tree — has size `Θ(n |F|)`.

A compact representation of the *output map* (BDD, or “`G_32 = 0`”)
exists when the map is actually simple or the domain is tiny. HMAC
with two or more ARX layers, on a width whose cycles are longer
than `n`, is not that map.

SHA-512’s 512-bit state has expected cycle length `~ 2^{256}`.
`n = 2048` is far below wrap. The measured regime is the linear
one: `size(G_2048) ≈ 2048 size(F)` in this representation family.

Repeated rounds, fixed rotates, Ch/Maj, pad64, and baked midstates
are already in the DAG. They do not create cross-iterate sharing
beyond `O(1)` constants.

No production change. The 1-round polynomial collapse remains the
only case where `T` is cheaper than the walk, and only because `T`
is a simple function, not because a dense `T` hid a small circuit.
