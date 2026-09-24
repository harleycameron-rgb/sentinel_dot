# Legacy Log Migration and Key Handling

This guide covers moving logs written by the original `log.py` (unkeyed SHA-256, lax schema) to the hardened format (HMAC-SHA256, strict schema, anchored heads), and how to manage the HMAC key.

## 1. What changes

| Aspect | Legacy | Hardened |
|---|---|---|
| Entry hash | `SHA256(canonical_json(body))` | `HMAC-SHA256(key, canonical_json(body))` |
| Forgery resistance | None (anyone can re-chain) | Requires the key |
| Truncation detection | None | `expected_head=(next_seq, hash)` |
| Floats / NaN in `parameters` | Allowed (NaN written as invalid JSON) | Rejected; migration converts to exact strings |
| Unknown fields | Allowed and hashed | Rejected |
| Negative `seq`/`round`, empty names | Allowed | Rejected |

Entry content (`seq`, `msg_type`, `sender`, `round`, `action_type`, `parameters`, `permission_token`) is carried over unchanged except for float conversion. **Every `prev_log_hash` and `entry_hash` changes**, so any external reference to a legacy hash must be remapped via the migration report.

## 2. Before you start

1. **Stop all writers.** Migration reads a snapshot; appends during migration are lost from the destination. Pause the permission engine or take the log offline.
2. **Record the legacy head.** If you have an anchored copy of the last legacy `entry_hash` (e.g. from a round-boundary record, a ticket, or a backup), have it ready. Without it, truncation of the legacy log cannot be detected.
   ```python
   from legacy.legacy_log import AppendOnlyLog as Old
   legacy_head = Old("ledger.jsonl").last_hash()   # only trustworthy if taken before any possible tamper
   ```
3. **Back up the source** (`cp ledger.jsonl ledger.legacy.jsonl`). Migration never modifies `src`, but keep an immutable copy as the audit trail.
4. **Dry-run verification** with the legacy verifier:
   ```python
   from legacy.legacy_log import verify_log as old_verify
   ok, issues = old_verify("ledger.jsonl"); assert ok, issues
   ```
5. **Check for torn tails.** If the file doesn't end in `\n`, a crash left a partial line. Inspect it; if it's clearly an incomplete write, truncate it manually (or append once via `AppendOnlyLog(path, repair_torn_tail=True)`) and record that you did so.
6. **Provision the key** (section 5) before migrating.

## 3. Procedure

```python
import json, os
import log as L

key = load_key()   # see section 5; CLI: `sentinel_dot keygen` — never hard-code

report = L.migrate_legacy_log(
    src="ledger.jsonl",
    dst="ledger.v2.jsonl",
    key=key,
    expected_legacy_head=legacy_head,   # strongly recommended
    convert_floats=True,                # False = abort if any float is present
)

# Post-migration verification
ok, issues = L.verify_log("ledger.v2.jsonl", key=key,
                          expected_head=tuple(report["new_head"]))
assert ok, issues

# Persist the report as the migration record
with open("ledger.migration.json", "w") as f:
    json.dump({**report, "src": "ledger.jsonl", "dst": "ledger.v2.jsonl",
               "key_id": KEY_ID}, f, indent=2)
```

Then cut over:

1. Point writers at `ledger.v2.jsonl` (or `os.replace` it onto the original path once the legacy copy is archived).
2. Construct every writer and verifier with the same key: `AppendOnlyLog(path, key=key)`, `verify_log(path, key=key, expected_head=...)`.
3. Store `report["new_head"]` in your external anchor (see section 6).
4. Resume writers.

### Refusal cases

Migration raises and writes nothing (an existing `dst` is left untouched) when:

| Error | Cause | Action |
|---|---|---|
| `entry hash mismatch (tampered?)` | Entry edited after writing | Investigate; do **not** re-sign. Restore from backup. |
| `broken chain` / `seq N != M` | Entry deleted, inserted or reordered | Same as above. |
| `legacy head mismatch` | Log truncated, or wrong file | Locate the full log. |
| `TornWriteError` | Partial final line | See step 2.5. |
| `invalid JSON` | Corrupt line | Investigate; restore from backup. |
| `unknown fields [...]` | Legacy entries with extra keys | Decide whether the fields matter. If they do, extend `REQUIRED_FIELDS` deliberately. If not, strip them in a separately audited pre-pass (this invalidates legacy hashes, so re-anchor first). |
| `fails strict schema` | e.g. negative `round`, empty `sender`, floats with `convert_floats=False` | Fix upstream data in an audited pre-pass, or accept conversion. |
| `dst must differ from src` | In-place migration attempted | Use a new path. |

### Float conversion

Floats become their Python `repr` string, which round-trips exactly (`float("0.1") == 0.1`). `NaN`, `Infinity`, `-Infinity` become those literal strings. `report["converted_floats"]` lists every converted path (`line12.parameters.nested[0].g`). Consumers (e.g. the permission engine, replay) must parse these back with `float()` where numeric values are needed. For new writes, prefer scaled integers (e.g. µs/day as `int`) over strings.

### Hash remapping

The migrated log has new hashes. If other systems store legacy `entry_hash` values, build a map from the two files, which are line-aligned:

```python
old = [json.loads(l)["entry_hash"] for l in open("ledger.legacy.jsonl")]
new = [json.loads(l)["entry_hash"] for l in open("ledger.v2.jsonl")]
remap = dict(zip(old, new))
```

Keep the legacy file and this map together; they are the proof that the v2 chain is a faithful re-signing of the legacy chain.

## 4. Rollback

Migration is non-destructive. To roll back: stop writers, point them back at the legacy file, and discard `ledger.v2.jsonl`. Any entries appended to v2 after cutover must be replayed into the legacy log manually (note they may contain no floats, so they are legacy-compatible). The legacy verifier accepts files extended by the new code in **unkeyed** mode only.

## 5. Key handling

### Generation

```python
import secrets
key = secrets.token_bytes(32)   # 256-bit, matches HMAC-SHA256 block security
```

Never derive the key from a password, a hostname, or anything in the repo.

### Storage

- Store in a secret manager (AWS Secrets Manager, GCP Secret Manager, Vault, 1Password, OS keychain). Load at process start:
  ```python
  import base64, os
  def load_key() -> bytes:
      k = base64.b64decode(os.environ["LEDGER_HMAC_KEY"])   # injected by the secret manager
      if len(k) < 32: raise RuntimeError("LEDGER_HMAC_KEY too short")
      return k
  ```
- Never commit keys, write them to the log, print them, or place them in `parameters`.
- Give each key a non-secret **key ID** (e.g. `ledger-2026-09`) and record it in the migration report and your anchor store, so verifiers know which key applies.

### Who holds the key

The HMAC key is symmetric: **anyone who can verify can also forge**. Limit it to the permission engine / log writer and the auditors you trust to write. If verifiers must not be able to write (e.g. third-party auditors), use Ed25519 mode (next section).

### Ed25519 mode (independent auditors)

- Generate: `sentinel_dot keygen --ed25519 writer` creates `writer.key` (PKCS#8, mode 0600, refuses to overwrite) and `writer.pub`. Set `SENTINEL_DOT_SIGNING_PASSWORD` first to encrypt the private key.
- The writer loads `Ed25519Signer.from_file("writer.key")`. The private key belongs in the same secret manager as an HMAC key would.
- Auditors get `writer.pub` only, plus the key ID (`ed25519:<16 hex>`, the first 16 hex of SHA-256 of the raw public key) for out-of-band confirmation.
- Migrate legacy logs straight into signed form: `sentinel_dot migrate old.jsonl new.jsonl --signing-key writer.key`, then verify with `sentinel_dot verify new.jsonl --pubkey writer.pub`.
- Rotation works the same as for HMAC (new segment per key). Each segment verifies only with its own public key. Publish old public keys permanently; they're not secret.
- Compromise: an attacker with the private key can re-sign any unanchored history. Bitcoin anchors (section 6) bound the damage: anchored heads can't be changed.

### Rotation

Logs are immutable, so rotation means starting a new segment, not re-signing old entries:

1. At a `round_boundary`, stop writers and anchor the current head `(next_seq, hash)` under the **old** key ID.
2. Start a new log file with the **new** key. Its first entry should be a `round_boundary` whose `parameters` record the previous segment: `{"prev_segment": "ledger.v2.jsonl", "prev_head_seq": N, "prev_head_hash": "<hex>", "prev_key_id": "ledger-2026-09"}`.
3. Keep the old key (read-only, verification only) for as long as the old segment must remain verifiable.
4. Verification of the full history = verify each segment with its own key and anchored head, and check each segment's first entry points to the previous segment's head.

Alternatively, `migrate_legacy_log`'s re-chaining logic can re-sign a whole verified log under a new key, but that changes every hash; use it only when the old key is compromised (below).

### Compromise

If the key leaks, an attacker can forge a fully valid chain. Response:

1. Revoke the key; generate a new one.
2. Verify every segment against **externally anchored heads** recorded before the leak. Entries up to the last pre-leak anchor are trustworthy; anything after is suspect.
3. Re-sign the trusted portion under the new key (re-use the migration routine on a truncated copy ending at the anchor), then re-anchor.
4. Treat post-anchor entries as untrusted until independently reconciled.

This is why external anchoring matters: the key protects against forgery by outsiders; the anchor limits the damage when the key itself is lost.

## 6. Head anchoring

`verify_log` only detects truncation if it is given a head stored somewhere the attacker can't also edit. Options, from simplest:

- A separate append-only store (database row, object storage with versioning/object lock).
- The permission engine's own state, updated on each `round_boundary`.
- A signed or timestamped external record (RFC 3161 timestamping, a git commit, a ticket).
- **Bitcoin via OpenTimestamps** (`sentinel_dot anchor create|upgrade|audit`). This is the strongest option, because it protects even against the key holder. Anchor records and `.ots` proofs live in `<log>.anchors/`. Back them up with the log: losing a proof loses that protection.

Record `(key_id, next_seq, entry_hash, timestamp)` at least once per round, and always after migration and rotation.

## 7. Checklist

- [ ] Writers stopped
- [ ] Legacy head recorded from a trusted source
- [ ] Legacy file backed up and verified with the legacy verifier
- [ ] No torn tail (or repair documented)
- [ ] 32-byte key generated and stored in a secret manager, key ID assigned
- [ ] `migrate_legacy_log` succeeded; report saved with key ID
- [ ] `verify_log(dst, key, expected_head=new_head)` passes
- [ ] New head anchored externally (`sentinel_dot anchor create`; `upgrade` once confirmed)
- [ ] Hash remap saved alongside legacy file (if external references exist)
- [ ] Consumers updated to parse converted float strings
- [ ] Writers switched to keyed `AppendOnlyLog` and resumed
