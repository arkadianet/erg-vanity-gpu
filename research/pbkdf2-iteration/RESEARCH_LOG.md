# Research log — XOR of HMAC iterates

Author: arkadianet

Every avenue below is an exact-equivalence question. “No” means the
identity failed on the named model, not that SHA is nonlinear.

## H1. Univariate interpolant of F over GF(256) is sparse / linearized

Control: GF(2)-affine maps have interpolants supported on
`{0,1,2,4,…,128}` only (9 terms). Verified.

HMAC-like (4×2-bit words):

| model | nz(F) | nz(G2) | nz(G4) | nz(G8) |
|---|---|---|---|---|
| hmac r2 | 37 | 93 | 93 | 37 |
| hmac r4 | 245 | 256 | 255 | 255 |
| hmac r8 | 256 | 255 | 254 | 254 |
| arxhmac r4 | 253 | — | — | — |

G_n is not a sparser polynomial than F. At r≥4 it is denser. The XOR
does not cancel monomials. Abandoned as an evaluation algorithm: a
dense deg-255 interpolant is the 8-bit table trap.

## H2. Low-degree Abel / Schröder conjugacy over GF(256)

`ψ(F(x)) = ψ(x) ⊕ 1` with deg ψ ≤ 6: no non-constant solution on any
mixed model. Linear control also fails this *field* translation
(its cheap conjugacy is a GF(2)-linear change of coordinates, not a
univariate poly).

`ψ(F(x)) = α ψ(x)` deg ≤ 4, α ∈ {1,2,3,7,16,32,128,255}: the only
hits are constant invariants (α=1, column 0 of the system is zero).
No non-constant polynomial invariant of degree ≤ 4.

Affine ψ(z)=az⊕b conjugacy onto x² (Dickson/Frobenius in char 2):
none. Onto `{x⊕c, x+c, μx, x^{2^k}, rot}`: none, including on the
invertible ARX-HMAC.

Integer Abel `ψ(F(x)) ≡ ψ(x)+1 (mod 256)` for deg ≤ 2 integer
polynomials: none except the trivial `F(x)=x+odd`.

Continue: only if a *small-circuit* ψ appears. Degree-bounded
univariate search is closed for d≤6 / affine-over-the-field.

## H3. Linear semiconjugacy tower (conjugacy to a T-function)

New complete test: F is linearly conjugate to a T-function iff there
is a flag of linear forms a0..a{w-1} with (a0..ak)∘F a function of
(a0..ak) only. In particular a 1-bit linear quotient must exist.

| model | # 1-bit quotients | flag height |
|---|---|---|
| linear w=8 | 1 | **8** (full) |
| hmac r2 | 7 | 3 |
| hmac r3 / r4 / r8 | 0 | 0 |
| arx / arxhmac r≥2 | 0 | 0 |
| hmac 4×3 r3, r4 (w=12) | 0 | 0 |
| hmac 4×4 r3, r4 (w=16, 4k-sample) | 0 | 0 |

The r=2 height-3 flag is incomplete 2-bit diffusion (word 2 depends
only on word 0; avalanche `[4,4,2,4,0,0,1,2]`). It is gone at 3
rounds and does not return at larger width. Abandoned as a SHA-512
algorithm. Kept as the exact obstruction: rotations plus 3+ mixed
rounds kill every linear quotient.

## H4. HMAC sandwich Q = H_I ∘ H_O

Identity `F^n = H_O ∘ Q^{n-1} ∘ H_I` holds (tested n=1,2,3,5,8).

Q has the same interpolant sparsity, same algebraic degree, same
image size, and the same semiconjugacy height as F at r=2,4,8.
Iterating Q is the same work as iterating F. No win.

## H5. Unfolding / MPO ranks

hmac r4 value-tensor 16×16 rank of F^n is 16 (full) for n=1,2,4,8.
G8 the same. Graph-tensor MPO ranks (16, 139, 16) over R and GF(2).
No low-rank TT / MPO factorization. Abandoned.

## H6. Berlekamp–Massey over GF(256) on packed orbits

Linear-control LC is small and start-dependent. hmac r4 LC=9 for
three starts — that is the cycle length 9, not a key-independent
recurrence. hmac r8 LC=3–4, matching 2-cycles of a collapsed 2-bit
map (|im F|=21). Does not survive width. Abandoned.

## H7. Commutant of simple maps

After r≥3 the only commuting maps in
{XOR, add256, odd-mul, rot, 2-bit word-add} are the identities
(xor:0, add:0, mul:1, rot:0, word_add:0). No hidden centralizer
to quotient by.

## H8. Small-support nonlinear quotients

Every non-constant Boolean function of 2 or 3 input bits, as a
candidate I, tested for `I∘F` factoring through I.

| model | 2-bit hits | 3-bit hits |
|---|---|---|
| hmac r2 | ≥20 | ≥20 |
| hmac r3 | 0 | 0 |
| hmac r4 | 0 | 0 |
| hmac r8 | 0 | 20 (stopped) |

r=8 hits are the |im F|=21 collapse: many 3-bit functions become
accidental quotients of a 21-valued map. Full avalanche at r=4
(`[8]*8`); every output word depends on all four input words.
12-bit r=4: no 1-bit linear quotients. Abandoned.

## H9. Order-2 recurrence of a permutation (new, holds)

**Theorem.** If F is a permutation and Q := F ⊕ F^{-1}, then
for every x and every k≥1

    F^{k+1}(x) ⊕ F^{k-1}(x) = Q(F^k(x)).

Proof: substitute y=F^k(x) into Q(y)=F(y)⊕F^{-1}(y).

Real HMAC-SHA512 of a 64-byte block *is* a permutation (each
Davies–Meyer / SHACAL-2 half is a permutation of the block).
Reduced Ch/Maj models are not; two-key ARX is.

Differential test: `gn_order2` matches naive G_n on linear F and
on arx-hmac r=4 for n up to 256, all tested x.

**Cost.** Walking the recurrence still uses n evals of Q after
the first F. This is cheaper than n×F iff Cost(Q)<Cost(F), *or*
Q is affine (2w-bit affine state ⇒ G_n in O(w^3 log n)).

| model | deg F | deg Q | Q affine? | nz F / nz Q | Cost Q as F⊕F^{-1} |
|---|---|---|---|---|---|
| linear | 1 | 1 | **yes** | 9 / 9 | — |
| arx r2..8 | 7 | 7 | no | 253–255 / 251–254 | 2×F |
| arxhmac r2..8 | 7 | 7 | no | 251–253 / 253–254 | 2×F |

Q does not simplify. The identity is real; the saving is not.
This *is* the linear algorithm when F (hence Q) is affine, in
another basis. Continuing would require a cheaper circuit for
Q than for F at SHA-512 width. Constructive ARX inverse has
the same primitive count as F, and F ⊕ F^{-1} shares nothing.

## H10. Cycle / prefix-XOR (exact, does not scale)

`gn_cycle_xor`: walk until the orbit closes, then finish G_n from
the prefix and the cycle-XOR. Proven for every map (rho or
permutation). Differential-tested vs naive at n=2048 on linear,
mini-hmac r4, arx-hmac r4.

F-evals = min(n, p+L).

For a **permutation** the cycle through a random x has length
uniform in 1..2^w, so P(L < n) = n / 2^w.

| w | 5 random x, n=2048 | evals |
|---|---|---|
| 8 | 5/5 closed | 21–68 |
| 16 | 0/5 | 2048 |
| 32 | 0/5 | 2048 |

w=8 always wins (L≤256<2048): the table trap. BIP39 is w=512,
P(close) = 2048 / 2^{512}. The algorithm *is* the naive walk
plus an equality check that never fires.

## H11. Linear structures of G_n

Δ ≠ 0 is a linear structure of H if H(x⊕Δ)⊕H(x) is constant.
hmac r2 has 12 (under-mixed). hmac r4 / r8 and arxhmac r4 / r8:
**zero** linear structures of F, G2, G4, G8, G16, G2048.
G_n does not acquire a linear structure by XORing iterates.
12-bit hmac r4: none on F or G2; min derivative image *grows*
from 197 (F) to 774 (G2). Abandoned.

## H12. Image-size / 2-bit collapse (toy trap, recorded)

mini-hmac 4×2: |im F| is 16 (r2), 64 (r3), 110 (r4), **21** (r8).
Extra rounds on 2-bit words destroy information. Do not read
r=8 3-bit quotients or short BM periods as structure of HMAC.
Invertible ARX-HMAC stays bijective at every tested round count.

## Why continue / stop

Stopped searching representations whose only 8-bit win is
“functions of 8 bits have small tables” or “2-bit SHA has not
avalanched.”

The one identity that is new, exact, and lives at SHA-512 width
is H9 (order-2 recurrence of a permutation). It does not reduce
work unless Q is cheaper than F, which it is not on the
invertible models and has no reason to be for SHACAL-2.

Production PBKDF2 was not modified.
