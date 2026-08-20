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

## Next experiment, if any

Keep a *round-by-round* polynomial (80 sparse maps, not one 512-bit
ANF) and apply doubling to the *outer* `F` while reducing after each
composition through the 80-factor factorization. That is a different
encoding of the same question: do the 80-factor compositions stay
sparse when you XOR 2^k of them? The 2-round 16-bit measurement says
sparsity dies as soon as two nonlinear layers compose. Eighty layers
will not be kinder.

No production change. The 1-round collapse is real and is the thing
to remember: orbit-XOR *can* be cheaper than the walk, and we know
the property that makes it so.
