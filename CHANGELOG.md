# Changelog

## 0.2.0 — first public release

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
