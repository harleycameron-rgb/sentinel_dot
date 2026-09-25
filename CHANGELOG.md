# Changelog

## 0.3.0

### Added
- **Post-quantum signing with ML-DSA (FIPS 204):** `ml-dsa-44`, `ml-dsa-65` and `ml-dsa-87`, using the built-in support in `cryptography` 48 and later. Signatures use the FIPS 204 context string `sentinel_dot/entry/v1`.
- **Hybrid mode `hybrid-ed25519-ml-dsa-65`:** both signatures must verify. It can't be downgraded to Ed25519 alone.
- `load_signer()` / `load_verifier()` detect the algorithm from PEM files; hybrid keys are stored as two PEM blocks.
- CLI: `keygen --signing PREFIX --alg {ed25519,ml-dsa-44,ml-dsa-65,ml-dsa-87,hybrid}`. `verify --pubkey` and `migrate --signing-key` accept any algorithm.
- New `pq` extra (`cryptography>=48`). `mldsa_available()` for feature detection.
- 66 new tests: round trips per algorithm, tampering, rehashing, other keys, spoofed key IDs, bit flips, wrong lengths, context binding, each half of a hybrid forged, downgrade, migration and CLI.

### Changed
- `key_id` is now `<alg>:<16 hex>`, and each signature must be exactly the right length for its algorithm.
- The `all` and `dev` extras now require `cryptography>=48`. The `ed25519` extra still works with `cryptography>=41`.
- Without ML-DSA support, ML-DSA requests fail with a clear upgrade message, and Ed25519 still works.

### Compatibility
- Ed25519 signing is unchanged, so 0.2 signed logs, anchors and keys verify as-is. `Ed25519Signer` and `Ed25519Verifier` remain.

## 0.2.0

### Changed
- Renamed the project from `agentledger` to **`sentinel_dot`**: package `sentinel_dot`, import `sentinel_dot`, commands `sentinel_dot` / `sentinel-dot`.
- Environment variables: `AGENTLEDGER_KEY` → `SENTINEL_DOT_KEY`, `AGENTLEDGER_SIGNING_PASSWORD` → `SENTINEL_DOT_SIGNING_PASSWORD`.
- New anchor records use type `sentinel_dot-anchor/1`. Existing `agentledger-anchor/1` records and `.ots` proofs still verify, because the type isn't checked when reading.
- Log format, hashes and signatures are unchanged. Logs written by agentledger verify as-is.

### Documentation
- README: expanded "Bitcoin anchoring (OpenTimestamps)" into a full guide:
  - How it works: anchor record format, calendar submission, aggregation, confirmation, verification.
  - Lifecycle: `anchor create` → `status` → `upgrade` → `audit`, with real sample output and the Python API.
  - Reading an audit: report fields (`bitcoin_proven_through_seq`, `proven_no_later_than`, …) and every problem reason (`anchored_hash_mismatch`, `anchored_entries_missing`, `proof_invalid`, …).
  - `anchor verify-proof` for any file with an `.ots` proof, with the OpenTimestamps example (block 358,391).
  - Trust model: explorer agreement, trustless `ots verify` with your own node, calendar trust, "no later than" semantics.
  - Operational guidance: anchoring cadence, scheduled upgrades, backing up `.anchors/`, rewrite guard, offline writers.
  - Costs and privacy: free, hashes only, no interaction with Bitcoin funds.

### Added
- Ed25519 signing mode (`signer=` / `verify_key=`): auditors verify with public key only.
- Bitcoin anchoring via OpenTimestamps: `anchor create | upgrade | status | audit | verify-proof`; verification against block explorers (no node needed), which must agree.
- `migrate --signing-key`; `keygen --ed25519`.
- Optional extras: `ed25519`, `bitcoin`, `all`.

## 0.1.0 (unreleased, as agentledger)
- Hardened hash-chained log (HMAC, anchored heads, strict schema, crash safety), agent recorder, CLI, legacy migration.
