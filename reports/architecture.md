# Three-Round Multiparty ECDSA — Architecture & Deep Dive

## What This Project Is

A proof-of-concept C++ implementation of **threshold ECDSA** — a cryptographic protocol that lets a group of `n` parties collaboratively produce a standard ECDSA signature, where any `t+1` parties can sign but no individual party (or coalition smaller than `t+1`) ever holds or learns the full private key.

The scheme is based on **threshold CL encryption** (Class-group based encryption, specifically `CL_HSMqk`), which provides additive homomorphism that the signing rounds exploit heavily.

Default parameters in the CLI: `n=5` parties, `t=4` threshold (i.e., all 5 must participate to sign).

---

## Why CL Encryption (Not RSA / Paillier)?

CL-HSMqk (Hidden Subgroup Membership for q-th powers) operates over the class group of an imaginary quadratic field. Compared to Paillier encryption (another common choice for MPC):

- The plaintext space is naturally the **order of the EC group** (secp256k1 / secp384r1 / etc.), so no modular reduction headaches when encoding EC scalars.
- Encryption randomness is bounded tightly, which makes zero-knowledge proofs more efficient.
- All class group arithmetic is done with **GMP big integers** (`Mpz`) via the BICYCL library.

---

## Repository Layout

```
Three-Round-Multiparty-ECDSA/
│
├── include/
│   ├── bicycl/          ← git submodule (BICYCL library — class group crypto)
│   └── trecdsa/         ← PUBLIC API (what callers include)
│       ├── Types.h      ← GroupParams, Signature, SecurityLevel
│       ├── Protocol.h   ← Protocol (run_dkg / run / verify)
│       ├── Errors.h     ← ProtocolError exception
│       └── Utils.h      ← randomize_message, select_parties (test helpers)
│
├── src/
│   ├── compat/
│   │   ├── bicycl_compat.h   ← namespace aliases + two ZK proof classes not in upstream BICYCL
│   │   └── bicycl_utils.h    ← Lagrange interpolation (EC group + class group), factorial
│   └── protocol/
│       ├── party.h           ← Party class (internal), round data structs
│       ├── party.cpp         ← Party round handlers
│       ├── protocol.cpp      ← Protocol::Impl, DKG, signing orchestration
│       ├── types.cpp         ← GroupParams::Impl, Signature::Impl
│       └── protocol_unit.cpp ← Unity build: #includes the three .cpp files above
│
├── apps/cli/
│   └── main.cpp         ← Demo: DKG → select parties → sign → verify → print timing
│
├── tests/
│   ├── smoke_test.cpp   ← Full happy-path end-to-end
│   ├── failure_test.cpp ← Bad-input error handling
│   └── api_test.cpp     ← Public API contracts
│
└── CMakeLists.txt       ← Builds trecdsa_core (static lib) + trecdsa_cli + tests
```

---

## Public API (the three headers under `include/trecdsa/`)

### `Types.h`

| Type | Role |
|---|---|
| `SecurityLevel` | Enum selecting 112 / 128 / 192 / 256-bit security. Drives EC curve choice and CL parameter sizing inside BICYCL. |
| `GroupParams` | Holds all shared cryptographic parameters: EC group, hash algo, CL public parameters, `n`, `t`, `δ = n!`. Passed by reference into `Protocol`. Uses PIMPL to hide BICYCL types from callers. |
| `Signature` | An ECDSA signature `(r, s)` stored as two big integers. Also PIMPL — callers never touch the internals. |

### `Protocol.h`

```cpp
Protocol(GroupParams& params);

void run_dkg();
std::vector<Signature> run(party_set, message);      // returns signatures
void run(party_set, message, signatures_out);         // output-param overload
bool verify(signatures, message) const;
```

`Protocol` is the only thing a consumer needs. It manages all `n` `Party` objects internally.

### `Errors.h` / `Utils.h`

- `ProtocolError` — thrown on any protocol violation (threshold not met, bad inputs, DKG not run yet).
- `randomize_message(m)` — fills a vector with 4–255 random bytes via OpenSSL `RAND_bytes`.
- `select_parties(n, t)` — picks a random set of `t+1` party IDs from `{1…n}`.

---

## Internal Layer: `GroupParams::Impl`

Defined in `src/protocol/types.cpp`. This is the heart of the shared state:

```cpp
struct GroupParams::Impl {
    SecLevel sec_level;
    size_t n, t;
    Mpz delta;          // = n! (factorial of party count)
    ECGroup ec_group;   // secp256k1/384r1/etc. depending on security level
    HashAlgo H;         // SHA-256/384/512 depending on security level
    CL_HSMqk cl_pp;    // CL encryption public parameters (class group, bound, etc.)
};
```

`delta = n!` is used throughout the Lagrange interpolation for the class group — because CL secret key shares are integers (not field elements), interpolation needs to be done over **integers** rather than modulo the group order, and multiplying by `n!` clears all denominators.

---

## DKG: `Protocol::run_dkg()`

Distributed Key Generation creates two parallel sets of shares — one in the class group (for CL encryption) and one on the EC group (for ECDSA).

### CL secret key shares

```
α  ← random
sk = α · δ²        (master CL secret key)
f(X) = sk/δ + a₁X + a₂X² + … + aₜXᵗ    (random polynomial, degree t)
sk_i = f(i)        for each party i ∈ {1…n}
pk_i = h^sk_i      (CL public key share)
pk   = h^sk        (master CL public key)
```

The `δ²` factoring ensures Lagrange reconstruction over integers works cleanly.

### EC secret key shares

```
u  ← random mod q
X  = u·G            (ECDSA public key)
g(X) = u + b₁X + … + bₜXᵗ    (random polynomial, degree t)
x_i = g(i)          for each party i
X_i = x_i·G         (EC public key share)
```

Both polynomials are evaluated via Horner's method. After DKG, each `Party` holds `(sk_i, pk, all pk_j, x_i, X, all X_j)`.

---

## Signing Protocol (3 rounds + offline finalization)

Given a party set `S ⊆ {1…n}` with `|S| ≥ t+1` and a message `m`:

### Round 1 — Commit & Encrypt

Each party `i ∈ S`:

1. Sample **nonce share** `k_i ← Z_q` and **masking scalar** `φ_i ← Z_q`.
2. Compute EC point `R_i = k_i·G`.
3. Encrypt the masking scalar under the CL public key: `enc_φ_i = Enc_pk(φ_i; r_i)` with fresh randomness `r_i`.
4. **Commit** to `R_i`: `(com_i, open_i) = Hash(random_nonce ‖ R_i)`.
5. Produce two ZK proofs:
   - `π_DL`: Schnorr-style NIZK proving knowledge of `k_i` s.t. `R_i = k_i·G` (from BICYCL: `ECNIZKProof`).
   - `π_ZKAoK`: ZK proof of knowledge of the CL plaintext `φ_i` in `enc_φ_i` (from BICYCL: `CL_HSMqk_ZKAoKProof`).
6. **Broadcast**: `(enc_φ_i, com_i, π_ZKAoK)`.  
   Note: `(open_i, R_i, π_DL)` are kept **local** until round 2.

### Round 2 — Open & Scale

Each party `i ∈ S` receives all round-1 broadcasts:

1. **Verify** all `π_ZKAoK` proofs. Abort if fewer than `t+1` are valid.
2. **Aggregate** CL ciphertexts homomorphically:  
   `enc_φ = enc_φ_{j1} ⊕ enc_φ_{j2} ⊕ … = Enc_pk(φ_{j1} + φ_{j2} + …) = Enc_pk(φ)`.  
   where `φ = Σ φ_j` is the combined masking scalar (never known to anyone).
3. Compute **Lagrange coefficient** `ω_i = λᵢˢ(0)` in `Z_q` for the EC group.
4. Scale ciphertexts (CL scalar multiplication is also homomorphic):
   - `phi_x_i = ω_i · enc_φ = Enc_pk(ω_i · φ)` — encodes party i's contribution to `φ·x`.
   - `phi_k_i = k_i · enc_φ = Enc_pk(k_i · φ)` — encodes party i's contribution to `φ·k`.
5. Produce ZK proofs (`CL_HSMqk_DL_CL_ZKProof`) for both scalings, linking the plaintext to the EC point.
6. **Broadcast**: `(phi_x_i, phi_k_i, R_i, open_i, π_DL, π_DL_CL_x, π_DL_CL_k)`.

### Round 3 — Partial Decrypt

Each party `i ∈ S` receives all round-2 broadcasts:

1. **Verify** commitments: `Hash(open_j ‖ R_j) == com_j` for all `j`.
2. **Verify** all four ZK proofs per party. Abort if fewer than `t+1` pass all checks.
3. **Aggregate** nonce point and ciphertexts:
   - `R = Σ R_j` (EC addition — this is the ECDSA nonce point).
   - `c0 = Σ phi_k_j = Enc_pk(k · φ)` (sum of `phi_k` shares = encoding of `φ·Σω_j·k_j = φ·k`... wait, actually more nuanced — `c0 = Enc_pk(φ·k)` after Lagrange).
   - `c1_r = Σ phi_x_j = Enc_pk(φ · Σω_j·x_j) = Enc_pk(φ·x)`.
4. Extract `r = x-coord(R) mod q`.
5. Build the signature ciphertext:
   ```
   c1 = h(m)·enc_φ ⊕ r·c1_r
      = Enc_pk(h(m)·φ + r·φ·x)
      = Enc_pk(φ·(h(m) + r·x))
   ```
   So `c0 = Enc_pk(φ·k)` and `c1 = Enc_pk(φ·s·k)` where `s = k⁻¹(h(m)+rx)` is the target ECDSA `s`.
6. **Partially decrypt** both ciphertexts with own secret key share: `d_{i,0} = c0.c1^{sk_i}`, `d_{i,1} = c1.c1^{sk_i}`.
7. Produce ZK proofs of correct partial decryption (`CL_HSMqk_Part_Dec_ZKProof`).
8. **Broadcast**: `(d_{i,0}, d_{i,1}, π_pd_c0, π_pd_c1)`.

### Offline — Finalize

Each party `i ∈ S`:

1. **Verify** all partial decryption proofs. Abort if fewer than `t+1` valid.
2. **Lagrange-combine** partial decryptions (in the class group, using `cl_lagrange_at_zero`):
   - `m0 = DLog_F(c0.c2 · ∏ d_{j,0}^{-λⱼ}) = φ·k`
   - `m1 = DLog_F(c1.c2 · ∏ d_{j,1}^{-λⱼ}) = φ·(h(m)+rx)`
3. Compute signature:  
   `s = m0⁻¹ · m1 = (φk)⁻¹ · φ(h(m)+rx) = k⁻¹(h(m)+rx)`  
   The masking scalar `φ` cancels — that was its only job.
4. Output `(r, s)`.

### Why the masking scalar `φ`?

CL decryption reveals the plaintext in the clear. Without `φ`, round 3 would decrypt `k` and `x` directly, leaking the private key and nonce. `φ` is a blinding factor that ensures what gets decrypted is always `φ·(something)`, which only reveals `s` after the cancellation — never `k` or `x` individually.

---

## Verification

Standard ECDSA:

```
u1 = h(m)·s⁻¹ mod q
u2 = r·s⁻¹ mod q
R' = u1·G + u2·X
check: x-coord(R') mod q == r
```

Performed against the `sig_public_key = X` stored on the `Protocol` object after DKG.

---

## Zero-Knowledge Proofs Used

| Proof | Where | What it proves |
|---|---|---|
| `ECNIZKProof` (from BICYCL) | Round 1 | Party knows `k_i` s.t. `R_i = k_i·G` |
| `CL_HSMqk_ZKAoKProof` (from BICYCL) | Round 1 | Party knows plaintext `φ_i` in `enc_φ_i` |
| `CL_HSMqk_DL_CL_ZKProof` (added in `bicycl_compat.h`) | Round 2 | Scalar used in CL multiplication equals the discrete log of the EC point (links `phi_x_i` to `X_i·ω_i` and `phi_k_i` to `R_i`) |
| `CL_HSMqk_Part_Dec_ZKProof` (added in `bicycl_compat.h`) | Round 3 | Partial decryption was computed correctly with the party's actual secret key share |

All proofs are **Fiat-Shamir NIZKs** — the challenge is derived from a hash of the proof commitment elements.

---

## Lagrange Interpolation: Two Flavors

`src/compat/bicycl_utils.h` implements two versions of Lagrange coefficient computation:

### EC group version (`lagrange_at_zero`)
Used in Round 2 for computing `ω_i` for the EC secret key sharing:
```
ω_i = ∏_{j∈S, j≠i} j/(j-i)   (mod q, q = EC group order)
```
Division is modular inverse. Output is a `BN` (big integer mod q).

### Class group version (`cl_lagrange_at_zero`)
Used in the offline phase for combining CL partial decryptions:
```
Δ·ω_i = δ · ∏_{j∈S, j≠i} j/(j-i)
```
Here `δ = n!` clears the denominators (since `j-i` always divides `n!`), making the result a plain integer `Mpz` — no modular inverse needed. This is why `delta = factorial(n)` is precomputed in `GroupParams::Impl`.

---

## Unity Build (`protocol_unit.cpp`)

```cpp
#include "types.cpp"
#include "party.cpp"
#include "protocol.cpp"
```

This is a single-translation-unit (unity) build pattern. All three `.cpp` files are compiled as one unit, giving the compiler full visibility to inline and optimize across them. It also means `party.h`, `bicycl_compat.h`, `bicycl_utils.h` etc. are **private** — not installed — while `include/trecdsa/` is the clean public interface.

---

## BICYCL Compatibility Layer (`src/compat/`)

BICYCL's upstream doesn't provide all the ZK proofs this protocol needs, so `bicycl_compat.h` adds two:

**`CL_HSMqk_DL_CL_ZKProof`** — Sigma protocol proving that a ciphertext `ct1 = scalar · ct0` (CL scalar mult) where `scalar` is also the discrete log of a given EC point `P = scalar·G`. Three-part check: two in the class group, one on the EC curve.

**`CL_HSMqk_Part_Dec_ZKProof`** — Sigma protocol proving that a partial decryption `d = c1^sk_i` was computed with the same `sk_i` used to generate `pk_i = h^sk_i`. Two-part check in the class group.

Both use the Fiat-Shamir heuristic with BICYCL's `HashAlgo`.

---

## Test Suite

### `smoke_test` — Happy path

```
n=5, t=2, sign with parties {1,2,3}
→ produces 3 signatures (one per participating party)
→ all 3 must pass standard ECDSA verify
```
Tests that the full pipeline produces correct, verifiable ECDSA signatures.

### `failure_test` — Error conditions

| Test | Setup | Expected |
|---|---|---|
| `expect_insufficient_parties_throw` | n=5, t=2, use only {1,2} (need ≥3) | `ProtocolError` thrown |
| `expect_out_of_range_party_throw` | n=5, t=2, use {1,2,6} (party 6 doesn't exist) | `ProtocolError` thrown |
| `expect_empty_message_throw` | n=5, t=2, use {1,2,3}, message=`[]` | `ProtocolError` thrown |
| `expect_tampered_message_fails_verify` | Sign message `m`, verify against `m` with bit-flip | `verify()` returns `false` |

### `api_test` — API contract

| Test | What it checks |
|---|---|
| `expect_public_api_getters_work` | `party_count()` and `threshold()` return correct values before and after DKG |
| `expect_run_overloads_match` | Return-value and output-param overloads of `run()` produce the same count of signatures |
| `expect_verify_without_dkg_throw` | Calling `verify()` before `run_dkg()` throws `ProtocolError` |

---

## Build System

```
CMakeLists.txt
├── trecdsa_project_options  (INTERFACE target: warning flags, sanitizer flags)
├── bicycl               (from submodule — EXCLUDE_FROM_ALL, marked as SYSTEM to suppress its warnings)
├── trecdsa_core         (STATIC library: protocol_unit.cpp + links bicycl, gmp, gmpxx, OpenSSL)
├── trecdsa_cli          (executable: apps/cli/main.cpp → links trecdsa_core)
└── tests/
    ├── trecdsa_smoke_test
    ├── trecdsa_failure_test
    └── trecdsa_api_test
```

Key build flags:
- `TRECDSA_WARNINGS_AS_ERRORS=ON` — used in CI's second job; all warnings become errors.
- `TRECDSA_ENABLE_SANITIZERS=ON` — ASan + UBSan; used in CI's third job with Clang.
- `CMAKE_EXPORT_COMPILE_COMMANDS=ON` — always on, outputs `compile_commands.json` for clang-tidy.

---

## External Dependencies

| Dep | Where | Purpose |
|---|---|---|
| `bicycl` | git submodule at `include/bicycl/` | Class group arithmetic, EC wrappers, ZK proofs, RNG |
| `libgmp` / `libgmpxx` | Homebrew (`/opt/homebrew`) | Arbitrary precision integers used by BICYCL |
| `OpenSSL` | Homebrew (`/opt/homebrew`) | `RAND_bytes` (randomness), EC group operations, SHA hashing |
| `CMake ≥ 3.29` | Homebrew | Build system |
| Homebrew LLVM 21 | `/opt/homebrew/opt/llvm/` | C++ compiler (Clang 21, C++17) |

Build command for this Mac:
```bash
cmake -S . -B build \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ \
  -DCMAKE_PREFIX_PATH=/opt/homebrew
cmake --build build -j$(sysctl -n hw.logicalcpu)
ctest --test-dir build --output-on-failure
```

---

## Security Properties (What This Achieves)

1. **Threshold signing**: Any `t+1` of `n` parties can sign; any fewer cannot. Correctness and security hold under the standard CL-HSMqk hardness assumption.

2. **No single point of failure on the key**: The private ECDSA key `x = Σ λᵢ·xᵢ` is never assembled in a single location. The CL key `sk` is similarly split.

3. **Publicly verifiable output**: The produced `(r, s)` is a standard ECDSA signature verifiable by anyone with the public key `X` — no special threshold machinery needed to verify.

4. **ZK-guarded rounds**: Every piece of data broadcast in rounds 1–3 comes with a zero-knowledge proof. Before a party uses another's contribution, it checks the proof — so a malicious party cannot inject wrong values without detection (as long as ≥ `t+1` parties are honest).

5. **Three-round interactive**: The protocol requires exactly 3 rounds of broadcast communication plus a local offline finalization step, which is optimal for this class of protocols.

**Caveat — Proof of Concept**: This is a centralized simulation (all parties run in the same process, no network). The `Protocol` class orchestrates rounds sequentially. A production deployment would need: network transport, parallel party execution, authenticated broadcast channels, and hardened ZK proof implementations.
