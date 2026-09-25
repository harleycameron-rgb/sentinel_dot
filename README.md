# sentinel_dot

**Tamper-evident action logs for AI agents.** Every tool call, result, refusal and round boundary your agent produces is written to an append-only JSONL file, chained with HMAC-SHA256. If anyone edits, deletes, reorders or forges an entry — or silently truncates the log — verification fails and tells you exactly where.

Core has zero dependencies (pure Python ≥ 3.9). Optional extras: `ed25519` (independent auditors), `pq` (post-quantum ML-DSA) and `bitcoin` (OpenTimestamps anchoring).

## Why

When an agent moves money, edits code, sends email or touches production, you need to answer *"what exactly did it do, and has this record been altered?"* Ordinary logs can be rewritten by anyone with file access. sentinel_dot gives you:

- **Forgery resistance** — entries are HMAC-signed, or public-key signed (Ed25519, **post-quantum ML-DSA**, or a hybrid of both) so **independent auditors verify with a public key and cannot forge**.
- **Bitcoin-anchored history** — log heads are timestamped into Bitcoin via OpenTimestamps, so even the key holder cannot later rewrite anchored history undetected.
- **Truncation detection** — anchor the head `(next_seq, hash)` outside the log; deleted tail entries are caught.
- **Crash safety** — exclusive file lock, `fsync` on every write, torn final lines detected (and optionally repaired).
- **Strict, cross-language-stable schema** — no NaN, no floats, no unknown fields, so hashes are reproducible anywhere.
- **Localized diagnostics** — a single tampered entry is reported once, not as a cascade.

## Install

```bash
pip install sentinel_dot              # core (also: pip install sentinel-dot)
pip install "sentinel_dot[ed25519]"   # + auditor signatures (Ed25519)
pip install "sentinel_dot[pq]"        # + post-quantum ML-DSA and hybrid (cryptography >= 48)
pip install "sentinel_dot[all]"       # + Bitcoin anchoring
# from source
pip install -e ".[dev]"
```

## Quick start

```bash
export SENTINEL_DOT_KEY=$(sentinel_dot keygen)   # store in a secret manager in production
```

```python
from sentinel_dot import AgentRecorder, load_key

rec = AgentRecorder("agent.jsonl", agent_id="planner", key=load_key())

@rec.tool
def web_search(query: str) -> list:
    ...

@rec.tool(token=lambda to, amount: permissions.grant("pay", to, amount))
def send_payment(to: str, amount: int):
    ...

web_search("orrery gear ratios")        # logs tool:web_search + tool_result:web_search
rec.reject("tool:delete_db", "policy: destructive action")
boundary = rec.next_round("task complete")
anchor_store.save(rec.head())            # anchor externally
```

Verify:

```bash
sentinel_dot verify agent.jsonl --key-env SENTINEL_DOT_KEY --expect-seq 4 --expect-hash <hex>
sentinel_dot show agent.jsonl -n 10
sentinel_dot head agent.jsonl
```

Exit codes: `0` OK, `1` verification failed, `2` error.

## Independent auditors (Ed25519)

HMAC is symmetric: whoever can verify can also forge. With Ed25519 the writer keeps the private key and auditors get only the public key.

```bash
sentinel_dot keygen --ed25519 writer        # writer.key (0600, keep secret), writer.pub (share)
# optional: export SENTINEL_DOT_SIGNING_PASSWORD=... to encrypt writer.key
```

```python
from sentinel_dot import AgentRecorder
from sentinel_dot.signing import Ed25519Signer
rec = AgentRecorder("agent.jsonl", agent_id="planner", signer=Ed25519Signer.from_file("writer.key"))
```

Auditor, public key only:

```bash
sentinel_dot verify agent.jsonl --pubkey writer.pub --expect-seq 42 --expect-hash <hex>
```

In signing mode `entry_hash` is plain SHA-256 (so auditors can recompute it) and each entry carries `signature` (Ed25519 over `entry_hash`) and `key_id`. HMAC and Ed25519 modes are mutually exclusive. Detected: content edits, re-hashed chains without the private key, another key's signatures, spoofed `key_id`, stripped signatures.

## Post-quantum signatures (ML-DSA)

Ed25519 is secure today, but a large enough quantum computer could forge its signatures. Logs are often kept for years, so sentinel_dot also supports **ML-DSA** (FIPS 204, the NIST post-quantum signature standard), and a **hybrid** mode that needs both signatures to verify.

| `--alg` | Security | Signature | Entry size* | Use when |
|---|---|---|---|---|
| `ed25519` | classical | 64 B | ~0.5 KB | Short-lived logs, smallest files |
| `ml-dsa-44` | post-quantum, NIST category 2 | 2,420 B | ~5 KB | PQ at the lowest cost |
| `ml-dsa-65` | post-quantum, NIST category 3 | 3,309 B | ~7 KB | Recommended PQ default |
| `ml-dsa-87` | post-quantum, NIST category 5 | 4,627 B | ~10 KB | Highest assurance |
| `hybrid` | Ed25519 **and** ML-DSA-65 | 3,373 B | ~7 KB | Long-lived audit trails during the PQ transition |

\*Signatures are stored as hex, so they take twice their byte size on disk. On a typical machine ML-DSA-65 signs in about 1 ms and verifies in about 0.2 ms.

```bash
sentinel_dot keygen --signing writer --alg hybrid       # writer.key (0600) + writer.pub
sentinel_dot verify agent.jsonl --pubkey writer.pub     # algorithm detected from the key
sentinel_dot migrate old.jsonl new.jsonl --signing-key writer.key
```

```python
from sentinel_dot import AgentRecorder, load_signer
rec = AgentRecorder("agent.jsonl", agent_id="planner", signer=load_signer("writer.key"))
```

How it works:

- **Hybrid keys:** the `key_id` names the algorithm (for example `ml-dsa-65:3f9a…` or `hybrid-ed25519-ml-dsa-65:…`), and the key files contain two PEM blocks. A hybrid signature is the Ed25519 signature followed by the ML-DSA-65 signature. **Both must verify.** Forging one needs breaking Ed25519 *and* ML-DSA, and an auditor holding only the Ed25519 half can't be tricked into accepting a hybrid log.
- **Domain separation:** ML-DSA signs with the FIPS 204 context string `sentinel_dot/entry/v1`, so a signature made for another application can't be replayed here. Ed25519 signing is unchanged from 0.2, and existing signed logs keep verifying.
- **Size checks:** each signature must be exactly the right length for its algorithm, which is checked before any cryptography runs.
- **Mixing algorithms:** one log uses one key. To switch algorithms, start a new segment (see key rotation in `docs/MIGRATION.md`) or migrate.
- **Bitcoin anchoring:** anchors rely only on hashes (SHA-256), so they're unaffected by quantum attacks on signatures. Together, ML-DSA signing and Bitcoin anchoring leave no quantum-vulnerable step in the chain of evidence.

## Bitcoin anchoring (OpenTimestamps)

Signatures prove who wrote each entry. They can't stop the key holder from rewriting history and re-signing it. Anchoring covers that gap: you record the log's current head in the Bitcoin blockchain through [OpenTimestamps](https://opentimestamps.org). This proves the log was in that exact state no later than a given block. Nobody can change anchored history afterwards without it being detectable, not even you.

```bash
pip install "sentinel_dot[bitcoin]"    # adds opentimestamps-client (provides `ots`)
```

### How it works

1. **Anchor record.** `anchor create` writes a small JSON record of the current head to `<log>.anchors/anchor-<next_seq>.json`:
   ```json
   {"created_utc":"2026-09-25T00:00:00Z","hash":"<entry_hash of last entry>","key_id":"ed25519:…","log":"agent.jsonl","next_seq":42,"type":"sentinel_dot-anchor/1"}
   ```
2. **Submission.** The record's SHA-256 goes to several public OpenTimestamps calendars, which return a pending proof (`anchor-…json.ots`). Only that 32-byte hash leaves your machine, never log contents.
3. **Aggregation.** Each calendar combines thousands of submissions into a Merkle tree and puts the root in a single Bitcoin transaction. That's why it's free.
4. **Confirmation.** Once the transaction is mined and confirmed, usually within a few hours, `anchor upgrade` swaps the pending proof for a complete path from your record to that block's Merkle root.
5. **Verification.** Anyone with the log, the anchor record and the `.ots` file can check it. The check recomputes the proof's commitment and compares it to the Merkle root of the block at the attested height.

### Lifecycle

```bash
# 1. Anchor the current head (for example after each round_boundary)
sentinel_dot anchor create agent.jsonl

# 2. Check progress: shows pending calendars or confirmed block heights
sentinel_dot anchor status agent.jsonl

# 3. A few hours later: fetch Bitcoin attestations for all pending proofs
sentinel_dot anchor upgrade agent.jsonl

# 4. Full audit: chain + signatures + anchors + Bitcoin proofs
sentinel_dot anchor audit agent.jsonl --pubkey writer.pub --require-confirmed
```

A fresh anchor looks like this (real output, trimmed):

```json
{
  "record": "agent.jsonl.anchors/anchor-0000000002.json",
  "proof":  "agent.jsonl.anchors/anchor-0000000002.json.ots",
  "pending": [
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://btc.calendar.catallaxy.com",
    "https://finney.calendar.eternitywall.com"
  ],
  "bitcoin": []
}
```

The same steps from Python:

```python
from sentinel_dot import anchor as A

A.create_anchor("agent.jsonl")
A.upgrade_anchors("agent.jsonl.anchors")
report = A.check_log_against_anchors("agent.jsonl", verify_key=verifier, require_confirmed=True)
print(report["bitcoin_proven_through_seq"], report["proven_no_later_than"])
```

### Reading an audit

`anchor audit` returns exit code `0` if everything checks out and `1` otherwise, plus a JSON report:

| Field | Meaning |
|---|---|
| `ok` | No problems found |
| `bitcoin_proven_through_seq` | Highest entry `seq` covered by a confirmed anchor that still matches the log |
| `proven_no_later_than` | Block time (UTC) of that anchor. The log provably contained those entries by then |
| `anchors[]` | Per anchor: `in_log` and `proof.status` (`confirmed`, `pending`, `no_proof`, …) |
| `problems[]` | Every failure, with a reason |

| Problem reason | What happened |
|---|---|
| `anchored_hash_mismatch` | The entry at an anchored position has changed. History was rewritten, even if re-signed with a valid key |
| `anchored_entries_missing` | The log is shorter than an anchor says it was, so it was truncated |
| `proof_invalid: digest_mismatch` | The anchor record was edited after stamping |
| `proof_invalid: merkle_root_mismatch` | The proof doesn't match the real block. It's forged or corrupt |
| `proof_unconfirmed` / `proof_missing` | Still pending, or no `.ots` file (only reported with `--require-confirmed`) |
| other `D1` reasons | Chain or signature failures from `verify_log` |

Entries appended after the latest anchor are allowed. They're simply not yet Bitcoin-proven.

### Verifying any proof

`verify-proof` works on any file with an `.ots` proof, not just sentinel_dot records:

```bash
sentinel_dot anchor verify-proof anchor-0000000042.json          # uses anchor-0000000042.json.ots
sentinel_dot anchor verify-proof report.pdf --ots report.pdf.ots
```

Tested against the official OpenTimestamps example proof, it confirms Bitcoin block 358,391 (2015-05-28T15:41:18Z).

### Trust model

- **No Bitcoin node required.** Block headers are fetched from Blockstream and mempool.space. **Both must agree**, and a disagreement is an error. That means trusting those explorers for the header, not for your data.
- **Fully trustless option.** Run `ots verify anchor-….json.ots` against your own Bitcoin node (`--bitcoin-node`).
- **Calendars aren't trusted for correctness.** A dishonest calendar can only fail to confirm your timestamp; it can't forge one. Submitting to several calendars covers that.
- **Direction of proof.** An anchor proves the log existed **no later than** the block time. It says nothing about how long before.

### Operational guidance

- **When to anchor:** after every `round_boundary`, or on a schedule (hourly or daily). Anchors are cheap, and each one limits how much history is exposed.
- **Upgrading:** run `anchor upgrade` on a schedule (for example every few hours). Calendars keep pending commitments for a long time, but upgrade within days.
- **Backups:** keep `<log>.anchors/` with the log. **Losing an `.ots` file loses that protection.** The files are small and not secret, so copy them anywhere, including somewhere public.
- **Rewrite guard:** `anchor create` refuses to overwrite an existing record with a different hash at the same position, because that's itself a sign the log was rewritten.
- **Offline or air-gapped writers:** `write_anchor_record()` needs no network. Copy the record to an online machine and run `ots stamp` there.

### Costs and privacy

- **Cost:** free. The public calendars pay the Bitcoin fees and batch everyone's timestamps together.
- **Privacy:** the calendars and the blockchain only ever see hashes. Your log, anchor records and proofs stay with you. Anchoring never touches Bitcoin transactions or balances, and can't move or moderate anything on the network.

## Entry format

```json
{"action_type":"tool:web_search","entry_hash":"…","msg_type":"action","parameters":{"args":["orrery gear ratios"],"kwargs":{}},"permission_token":null,"prev_log_hash":"000…0","round":0,"sender":"planner","seq":0}
```

`msg_type` ∈ `action`, `rejection`, `round_boundary`, `malformed_rejection`. The recorder coerces floats to exact strings and arbitrary objects to `repr`; the low-level `AppendOnlyLog` rejects them.

## What it detects

| Attack / failure | Detected as |
|---|---|
| Edited entry | `entry_hash_mismatch` (that line only) |
| Deleted / inserted / reordered entry | `seq_mismatch`, `prev_hash_mismatch` |
| Tail truncation | `head_mismatch` (needs anchored head) |
| Full rewrite without key | `entry_hash_mismatch` / `signature_invalid` |
| One half of a hybrid signature forged | `signature_invalid` |
| Rewrite by the key holder, re-signed | `anchored_hash_mismatch` (Bitcoin anchor) |
| Truncation below an anchored head | `anchored_entries_missing` |
| Crash mid-write | `torn_final_line` / `TornWriteError` |
| Re-encoded JSON, NaN, extra fields | `non_canonical_encoding`, `invalid_json`, `schema_violation` |

## Threat model and limits

- HMAC is symmetric: **anyone holding the key can forge**. Use public-key signing when auditors must not be able to write.
- Ed25519 is not quantum-resistant. For logs that must stay trustworthy for years, use `ml-dsa-65` or `hybrid`.
- Anyone holding the private key can rewrite and re-sign **unanchored** entries. Only history covered by a confirmed Bitcoin anchor is protected from the key holder.
- Anchors prove "no later than", not "no earlier than". Confirmation normally takes a few hours.
- The log proves integrity of *what was recorded*, not that the agent recorded everything. Wrap every side-effecting tool.
- Truncation detection is only as strong as where you store the anchored head.
- File locking uses `fcntl` (Linux/macOS). Windows has no cross-process lock yet.

## Migrating legacy logs

Logs from the original unkeyed format migrate with full verification first — tampered logs are refused, never re-signed:

```bash
sentinel_dot migrate old.jsonl new.jsonl --key-env SENTINEL_DOT_KEY --legacy-head <hex>
```

See [docs/MIGRATION.md](https://github.com/harleycameron-rgb/sentinel_dot/blob/main/docs/MIGRATION.md) for the full procedure, key generation, rotation and compromise response.

## Development

```bash
pip install -e ".[dev]" && pytest          # offline suite
pytest -m network                          # live calendars + explorers
```

## License

Apache-2.0
