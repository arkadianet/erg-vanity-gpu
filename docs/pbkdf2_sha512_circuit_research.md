# SHA-512 compression cost on the PBKDF2 hot loop

Author: arkadianet

First-principles experiment. No web retrieval. Production kernels were
not modified. This VM has no RTX GPU, so SASS / occupancy / hashes-sec
were not measured here. Circuit exactness was measured on CPU.

---

## Executive conclusion

No exact cheaper SHA-512 *round or schedule representation* was found
that would cut the computational work of the 2048-step PBKDF2 chain by
≥10%. Mixed-operand 2-rotate forms of `Σ1+Ch` and `Σ0+Maj` missed on
64-bit samples; `+Ch` is injective in the Σ argument at 8/12/16-bit so
a missing rotate cannot hide inside the add; the HMAC-64 first expand
is exactly the known 22-σ form (32→22) and does not extend past `W[31]`;
two-round fusion does not shorten dependency depth. The only remaining
≥10% *possibility* is not a new circuit: it is whether this repo's
production `rotate(ulong)` + add chain already lowers to Ampere
`SHF`+`IADD3`+`LOP3`. That is a compiler question. It cannot be answered
without a dump of the production SASS on the target GPU.

---

## Baseline

### Production configuration (this tree, `main` @ 362b50b)

| Item | Value |
|------|--------|
| GPU implementation | OpenCL 1.2, not CUDA |
| Compile flags | `-cl-std=CL1.2` (`-cl-nv-verbose` only if `ERG_CL_VERBOSE=1`) |
| Target GPU (documented) | RTX 3080 Ti (sm_86 class), README 19 Aug 2026 |
| This VM | no `/dev/nvidia*`, no `clinfo`, no OpenCL ICD GPU |
| CUDA/toolchain here | rustc 1.97.1 after upgrade from 1.83.0; no `nvcc`, no `ptxas` |
| Hot kernel | `vanity_seed` → `bip39_entropy_to_seed` → `pbkdf2_sha512_mnemonic` |
| Isolated bench | `bench_pbkdf2`, default batch 262144, local size driver-chosen |
| Search launch | `local = min(256, device max, kernel WG limit)`, batch device-chosen (power of two, cap 1M) |
| SHA-512 source | `rotate((x),(ulong)(64-n))`, textbook `CH`/`MAJ`, 16-word in-place expand |
| HMAC | cached `I`/`O` midstates (`inner_h`/`outer_h`) |
| Occupancy / regs / SASS | **not measured** (no GPU) |

### Compression accounting (from the kernels, not the prompt)

```
hmac_sha512_init:          2 compressions   (ipad, opad)
U1 inner (12-byte salt):   1 compression    (special-cased "mnemonic"||INT32(1))
U1 outer:                  1 compression    (pad64 of inner digest)
iters 2..2048:             2047 × 2         (hmac_sha512_msg64_u8)
────────────────────────────────────────
Total per BIP39 seed:      4098 SHA-512 compressions
Hot loop:                  4094 pad64 compressions
```

Every `Uj` is XORed into `T` and fed to `Uj+1`. The 2048-step chain is
treated as unavoidable (closed by prior research).

### Documented RTX 3080 Ti performance (README, not this VM)

| Metric | Value |
|--------|--------|
| Isolated PBKDF2 | ~1600 ns/seed |
| Isolated share | ~56–64% of isolated pipeline time |
| Live search | ~590–610k seeds/s (`--index 1`) |

Variance, register count, occupancy, and instruction mix for *this*
checkout were not obtained. Those README figures are the competent
production baseline any later GPU candidate must beat.

### What is already in production vs the unmerged research branch

`origin/cursor/pbkdf2-hmac64-specialized-fbd7` has SHF-native
`ror64_shf`/`shr64_shf`, `bitselect` Ch/Maj, and a specialized HMAC-64
first expand. **None of that is on `main`.** Production still uses
generic `rotate(ulong)` and a full 32-σ first expand even though
`total_len` is always 128 in the hot path.

---

## Research performed

Classified before each experiment. Duplicates were not rerun.

| ID | Class | Branch |
|----|--------|--------|
| R1 | NEW | Reduced-width degeneracy of Σ amounts (4/8/12/16/64) |
| R2 | NEW | Mixed-operand 2-rotate catalog for `Σ1+Ch` (`xor_add`, `add_add`, `rot_sum`) |
| R3 | NEW | Same catalog for `Σ0+Maj` |
| R4 | EXTENSION | Injectivity of `+Ch` at 8-bit exhaustive / 12-/16-bit sampled |
| R5 | NEW | IADD3 association of `T1` / `a'` vs textbook `T1`/`T2` |
| R6 | EXTENSION | HMAC-64 first expand identities vs generic expand (200 messages) |
| R7 | EXTENSION | `W[t≥32]` identities: `=`, `⊕C`, `+C`, `ROTR`, pair-add, pair-xor (40 messages) |
| R8 | NEW | Shared rotate-amount overlap across Σ0/Σ1/σ0/σ1 |
| R9 | EXTENSION | Two-round dependency depth in an SHF/IADD3/LOP3 model |
| R10 | NEW | Dual rotate representation of `e` (`r=ROTR(e,14)`) |
| R11 | NEW | Ampere instruction-cost model of one round (floor / binary-add / soft-rotate) |
| R12 | NEW | Ch/Maj `bitselect` identities (source form, not a new function) |

Closed lines *not* repeated: orbits, memoisation, GF(2) linearisation,
operator powering, `F⊕F⁻¹`, Abel/Schröder, bitslice, CSA persistence,
HMAC inner/outer fusion, envelope CSE, 2-term linear Σ, the previous
15 textbook Σ+Ch fusions, STOKE walk that cannot delete a rotate.

---

## Best surviving optimisation

There is **no new exact circuit** to ship.

The strongest *exact* transformation that still exists is the already-
known HMAC-64 first expand (22 σ instead of 32) plus K-fold of
`W[8]=PAD` and `W[15]=1536`. Independently re-derived and checked
against the generic in-place expand on 200 random 8-word messages.

That is the known ~3% work cut. It is **not** a new discovery and it
does **not** extend: after `W[31]` the 40-message search found no
`W[t] ∈ {W[s], W[s]⊕C, W[s]+C, ROTR(W[s],k), W[i]+W[j], W[i]⊕W[j]}`
for the SHA-like constants and rotate amounts.

IADD3 association

```
T1  = (h + Σ1 + Ch) + (K + W)
e'  = d + T1
a'  = T1 + Σ0 + Maj
```

is bit-identical to the textbook form (400 random states) and is
already how `SHA512_R` is written (`h += …; d += h; h += …`). If the
compiler emits `IADD3`, this save is already in the binary. If it
emits a 2-input add chain, forcing 3-address form is an
implementation tweak, not a new hash.

---

## Strongest failed hypothesis

**Hypothesis (R2):** `Σ1(e)+Ch(e,f,g)` has an exact 2-rotate form
` (ROTR(X,a) ⊕ ROTR(Y,b)) + Z ` where `X,Y,Z` are cheap Boolean
atoms of `(e,f,g)` (not just `X=Y=e`, `Z=Ch`). That would drop 160
SHF per compression (one rotate from each Σ1), ~10% of the 1550-SHF
HMAC-64 floor.

**Why it looked promising:** `+` is not F₂-linear, so a rotate could
in principle be absorbed into the addend if `Z` is allowed to see
`f` and `g`. Previous search only tried 15 shapes that still rotated
`e` or `e⊕Ch`.

**Experiment:** 18-atom catalog × SHA-like amounts `{14,18,41,4,23,27,32,0}`
× three classes (`xor_add`, `add_add`, `rot_sum`), screened on 48
random 64-bit triples, survivors confirmed on 64 more.

**Result:** zero hits. The same for `Σ0+Maj`.

**Why it failed:** any form that is still “two rotates plus a Boolean”
either misses a circulant tap (and `+Z` cannot restore it — R4) or
rebuilds the third rotate inside `Z`, which is not cheaper.

---

## Circuit findings

### Σ1 + Ch

```
Σ1(e) = ROTR(e,14) ⊕ ROTR(e,18) ⊕ ROTR(e,41)
Ch    = g ⊕ (e ∧ (f ⊕ g))     = bitselect(g,f,e)
```

- `{14,18,41}` stay 3-distinct at widths 8, 12, 16, 64.
- At width 4, `14≡18 (mod 4)`. A 4-bit Σ1 model is degenerate and
  must not be lifted.
- Exhaustive 8-bit: `add(A,Ch)=add(B,Ch)` iff `A=B`. The 2-rotate
  projection equals Σ1 only at `e=0` (the zero vector).
- Mixed-operand 2-rotate catalog: empty.

No cheaper exact `Σ1+Ch`.

### Σ0 + Maj

```
Σ0(a) = ROTR(a,28) ⊕ ROTR(a,34) ⊕ ROTR(a,39)
Maj   = (a ∧ (b ⊕ c)) ⊕ (b ∧ c) = bitselect(a,b,a⊕c)
```

- Width 4 does *not* collapse Σ0 (`28,34,39 ≡ 0,2,3`).
- Mixed-operand 2-rotate catalog: empty.
- `bitselect` is the same function, one LOP3 per 32-bit half if the
  compiler cooperates. Production source still uses the 3-AND form.

### T1 / T2

```
T1 = h + Σ1 + Ch + K + W
e' = d + T1
a' = T1 + Σ0 + Maj
```

`T1` is consumed twice. IADD3 folding is exact and is the only
local lever that can move double-digit *instruction* count without
changing the function. It does not reduce SHF. Critical path remains
`Σ1 → T1 → a'` (and `e'`). Re-associating adds does not shorten that
path; it only cuts add-issue count if the compiler was using 2-input
adds.

CSA / delayed carry was already closed (each 3:2 needs a `<<1` =
2 SHF; +480 SHF/compression). Not reopened.

### Message schedule

HMAC-64 block: `W[0..7]=msg`, `W[8]=PAD`, `W[9..14]=0`, `W[15]=1536`.

First expand (verified): 22 runtime σ vs 32 generic. Constants
`σ1(1536)`, `σ0(PAD)`, `σ0(1536)` fold. `W[16]` and `W[17]` are
message-only and can be computed before round 0 (ILP, not fewer ops).
They share no intermediate with `Σ1(e)` / `Σ0(a)` of the first
rounds.

All 12 Σ/σ distances are distinct. No SHF is shared between schedule
and compression of a live value.

`W[32..79]`: no useful identity in 40 random pad64 expansions.

The standard 16-word in-place expand is not leaving free σ on the
table after the first window.

### Multi-round fusion

Two-round depth = 2 × one-round depth in the SHF/IADD3/LOP3 model.
`a'` / `e'` of round `t` are on the critical path of round `t+1`.
No cross-round CSE of Σ/Ch/Maj (avalanche). Expression explosion
killed further 4-/8-round algebraic expansion.

Dual representation `r = ROTR(e,14)`, `Σ1 = r ⊕ ROTR(r,4) ⊕ ROTR(r,27)`
is exact and still 3 rotates, plus one extra live value (register
trap).

---

## Machine-code findings

No PTX/SASS was produced. This VM has no NVIDIA compiler and no GPU.

Ampere integer model used for accounting (trained knowledge + the
source we would compile):

| 64-bit source op | 32-bit SASS floor |
|------------------|-------------------|
| `ROTR64` | 2× `SHF.R` |
| `SHR64` n<32 | 1× `SHF` + 1× `SHR` (~5 SHF per σ with 2 ROTR) |
| bitwise 3-input (`Ch`,`Maj`,3-xor) | 2× `LOP3` |
| 2-input or 3-input add | 2× `IADD3` (lo carry, hi carry-in) |

Per specialized HMAC-64 compression, SHF floor remains **1550** if
every rotate is a clean 2-SHF pair (prior accounting, unchanged).

Round model used in `sha512_circuit`:

| Lowering | SHF | IADD | LOP3 | total |
|----------|-----|------|------|-------|
| Floor (SHF+IADD3+LOP3) | 12 | 8 | 8 | 28 |
| Binary-add chain | 12 | 14 | 8 | 34 |
| Soft `rotate(ulong)` | 36 | 8 | 8 | 52 |

Dominant resources, if the floor is hit: **SHF from Σ/σ**, then IADD,
then LOP3. The dependency that limits a single thread is the T1 add
chain after Σ1, then `a'`/`e'` into the next round. Occupancy is the
latency-hiding mechanism; any candidate that raises the live set
above the current 24 ulong words (`a..h` + `W[0..15]`) is a register
trap.

Production source that the compiler sees:

```c
h += EP1_64(e) + CH64(e, f, g) + (k) + (w);
d += h;
h += EP0_64(a) + MAJ64(a, b, c);
```

That is already IADD3-shaped. `EP*` still go through `rotate(ulong)`.

---

## Benchmark table

| Candidate | Mathematical change | Expected op Δ | PTX/SASS | Regs | Occ. | Instr | Runtime | Throughput | Speedup |
|-----------|---------------------|---------------|----------|------|------|-------|---------|------------|---------|
| production baseline | — | — | **unmeasured** | ? | ? | ? | README ~1600 ns/seed | ~625k HMAC-64-equivalent seeds/s isolated | 1.00 |
| HMAC-64 first expand (known) | 32→22 σ in first window | ~3% SHF | unmeasured | same 16 W | ? | −10 σ | unmeasured | unmeasured | ~1.03 predicted |
| IADD3 assoc | none (same adds) | 0 if IADD3 already | unmeasured | 0 | 0 | −6 IADD/round *if* binary | unmeasured | unmeasured | 0–~14% of compression, compiler-dependent |
| SHF rotate source | none | 0 if already SHF | unmeasured | +0–2 | ? | −4 half-ops/ROTR *if* soft | unmeasured | unmeasured | 0–large, compiler-dependent |
| mixed 2-rotate Σ+Ch | — | — | — | — | — | — | — | — | **killed, 0 hits** |
| dual `ROTR(e,14)` | rewrite | 0 SHF, +1 live | — | +1 | worse | 0 | — | — | **killed** |
| 2-round fuse | rewrite | 0 | — | ? | ? | 0 | — | — | **killed** |

No candidate was timed on the target GPU. A single-run “win” is not
claimed.

---

## Negative findings (kill ledger)

```
Hypothesis: mixed-operand 2-rotate Σ1+Ch
Why it might work: + is not F2-linear; Z may see f,g
Required property: exact 64-bit equality, 2 rotates
Experiment: atom catalog × 3 classes × 48+64 triples
Exactness: n/a (no survivor)
Operation/instruction/register/occupancy delta: n/a
Measured speedup: n/a
Decision: KILLED
Reason: zero hits; +Ch injectivity (8-bit exhaustive) forbids hiding a rotate
```

```
Hypothesis: mixed-operand 2-rotate Σ0+Maj
Why / required / experiment: same structure, Σ0 amounts
Decision: KILLED
Reason: zero hits
```

```
Hypothesis: 4-bit exhaustive Σ1 is a valid reduced model
Why it might work: exhaustive search is cheap
Required property: amounts stay 3-distinct
Experiment: distinct-mod counts
Decision: KILLED as a lift vehicle
Reason: 14≡18 (mod 4). 8/12/16 remain valid.
```

```
Hypothesis: first-expand identities continue after W[31]
Why it might work: pad zeros might propagate
Required property: W[t] equals a cheap function of earlier W
Experiment: 40 random pad64 expansions, t=32..79
Decision: KILLED
Reason: no =, ⊕C, +C, ROTR, pair-add, pair-xor hits
```

```
Hypothesis: σ and Σ share a rotate of a live value
Why it might work: 12 distances, maybe a collision
Experiment: set equality of {1,8,7,19,61,6,28,34,39,14,18,41}
Decision: KILLED
Reason: all 12 distinct; W words are not working variables
```

```
Hypothesis: two-round block shortens the GPU critical path
Why it might work: ILP / reused rotations
Required property: depth(2) < 2×depth(1) or fewer issued ops
Experiment: depth model; prior word-DAG already showed no CSE
Decision: KILLED
Reason: a',e' feed the next Σ; depth doubles
```

```
Hypothesis: dual ROTR(e,14) representation drops a rotate
Why it might work: Σ1 amounts are 14, 14+4, 14+27
Experiment: identity check, 200 words
Decision: KILLED
Reason: exact, but still 3 rotates + extra live register
```

```
Hypothesis: IADD3 rewrite is a new ≥10% circuit
Why it might work: 5-term T1 + 3-term a' map to two IADD3
Experiment: 400-state exactness; cost model 8 vs 14 IADD/round
Decision: KILLED as a new circuit; SURVIVES as a compiler check
Reason: SHA512_R is already written this way. Save is 0 if IADD3
        is emitted. Not a representation change.
```

```
Hypothesis: CSA / delayed carry (reopen)
Decision: NOT REOPENED
Reason: closed; conversion before every Σ reintroduces a CPA and
        adds SHF. No new mechanism.
```

---

## Remaining possibilities

Genuinely unexplored, and only these:

1. **SASS of this production kernel on a real RTX.** Compare
   `rotate(ulong)` vs `ror64_shf`, textbook `CH` vs `bitselect`,
   and the add chain vs explicit 3-address form. This is the only
   item with a plausible ≥10% end-to-end story, and only if the
   current binary is *not* already at the SHF+IADD3 floor.
2. **Exact synthesis of `Σ1+Ch` outside the 2-rotate+Boolean class**
   (unbounded SAT over ADD/ROTR mixes with more than two rotates
   cancelled by a deep ADD tree). The 8-bit injectivity result makes
   a *shallower* win unlikely; a deep win would have to be a
   different 3-input 64-bit ARX circuit, which this pass did not
   brute-force.
3. **Occupancy-limited rewrite** that *adds* a little arithmetic to
   cut live registers below 24 ulongs. Not attempted; the current
   scalar `W[0..15]` path already exists to avoid local-memory spills.

Do not reopen: orbits, bitslice, CSA persistence, 2-term linear Σ,
pad64 after `W[31]`, 2-round algebraic cancellation.

---

## Final recommendation

```
CONTINUE — a specific unresolved avenue has ≥10% potential.
```

The avenue is **compiler lowering of the existing 80-round circuit**,
not a new round or schedule. The representation search in this pass
is empty: the conventional Σ/Ch/Maj/add/σ form, plus the known ~3%
HMAC-64 first expand, is the exact work.

On an RTX machine, the next measurement is:

1. `ERG_CL_VERBOSE=1` register/spill log for `bench_pbkdf2`.
2. PTX/SASS of `sha512_final_from_mid_u8` (production `rotate`) vs
   the unmerged `ror64_shf` + `SHA512_EXPAND16_HMAC64` path.
3. Isolated `--bench` with enough repeats to beat noise, against the
   ~1600 ns/seed README baseline.

If that dump already shows 2×`SHF` per `ROTR64` and `IADD3` for T1/`a'`,
the answer becomes **STOP** — the implementation is at the practical
integer-ALU floor for this dependency chain. If it shows `shr.b64` /
`shl.b64` / `or.b64` or a 2-input add chain, implement the unmerged
SHF + HMAC-64 expand source and re-bench. That would be an
implementation fix, not a new hash.

---

## How to re-run the circuit tests

```bash
cargo test --locked -p erg-vanity-crypto sha512_circuit
```

Production PBKDF2 / SHA-512 vectors in the same crate still pass
(`cargo test --locked -p erg-vanity-crypto --lib`).
