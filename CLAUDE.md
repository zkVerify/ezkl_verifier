# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust implementation of zkonduit's reusable EZKL Solidity verifier (Halo2 zk-SNARK protocol on BN254), optimized for zkVerify. The crate is `no_std`-compatible for embedded/bare-metal use.

## Build & Development Commands

Uses `cargo-make` for task automation:

```bash
cargo make build            # Release build
cargo make test             # Run tests (release mode)
cargo make format           # Auto-format with rustfmt
cargo make format-check     # Check formatting only
cargo make clippy           # Lint (strict: deny all warnings)
cargo make audit            # Security vulnerability check
cargo make cov              # Code coverage (requires cargo-llvm-cov)
cargo make build-bare-metal # no_std build for thumbv7em-none-eabi
cargo make ci               # Full local CI pipeline
cargo make ci-remote        # CI for PRs (format-check instead of format)
```

Run a single test: `cargo test <test_name> --release`

## Architecture

**Public API** — single entry point in `lib.rs`:
```rust
pub fn verify<H: CurveHooks>(raw_vka: &[u8], raw_proof: &[u8], pubs: &Public) -> Result<(), VerifyError>
```

The generic `H: CurveHooks` parameter enables custom elliptic curve implementations (hardware accelerators). Default `()` uses standard BN254 from arkworks.

**Verification pipeline** (all in `lib.rs`, ~3800 lines): reads VKA → hashes instances → generates Fiat-Shamir challenges (theta, beta, gamma, y, x, zeta, nu, mu) → evaluates gates/permutations/lookups → quotient check → EC point computations → final pairing check.

**Memory model**: EVM-style linear memory (`Vec<u8>`) with 32-byte word operations. VKA is loaded at `MEMORY_OFFSET` (0xa0), proof is read via offset-based `load_from_proof()`. Key constants: `PROOF_OFFSET = 0x84`, `PUBS_SIZE = 32`.

### Source files

- `lib.rs` — Core verification logic (40+ internal functions for the Halo2 protocol steps)
- `utils.rs` — Type conversion traits (`IntoFq`, `IntoFr`, `IntoU256`, `IntoBEBytes32`), EC point reading (`read_g1`/`read_g2`), memory ops (`mload`/`mload_u32`), challenge generation (`squeeze_challenge`)
- `errors.rs` — Error hierarchy: `VerifyError` (top-level) → `UtilityError`, `GroupError`, `FieldError`
- `types.rs` — Type aliases (`EVMWord`, `U256`, `Fr`, `Fq`, `G1`, `G2`, `Bn254`)
- `constants.rs` — Protocol constants (`DELTA`, bitmasks, `MAX_U32`)
- `should.rs` — Test fixtures and parameterized tests (rstest)

### Reference contracts

`contracts/` contains the Solidity reference implementations; `examples/` has two test vectors (`simple/` and `complex/`) with real proofs, VKAs, and public inputs.

## Key Conventions

- **No-std first**: `#![cfg_attr(not(feature = "std"), no_std)]` — uses `alloc` for heap. All changes must compile for both std and bare-metal targets.
- **No panics in verification**: all verification functions return `Result`. Use `snafu` for error context.
- **32-byte alignment**: VKA and proof inputs must be multiples of 32 bytes.
- **Zero clippy warnings**: CI enforces `--deny warnings` on clippy.
- **Release mode tests**: tests run with `--release` flag.
- **Custom arkworks forks**: `ark-bn254-ext` and `ark-models-ext` come from `zkVerify/accelerated-bn-cryptography` (pinned to v0.6.0).
