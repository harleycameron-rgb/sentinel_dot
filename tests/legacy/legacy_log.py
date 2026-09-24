"""
Hash-chained, append-only JSONL log.

Each entry:
    seq, msg_type, sender, round, action_type, parameters,
    permission_token, prev_log_hash, entry_hash

entry_hash = SHA256(canonical_json(entry_without_entry_hash))
prev_log_hash = previous entry's entry_hash (GENESIS_HASH for the first entry)

This module is deliberately dumb: it does not know what a "valid" action is.
That's the permission engine's job (see permissions.py / replay.py). The log
only guarantees byte-level tamper evidence and structural (schema) well-formedness.
"""

import json
import hashlib
from typing import Any, Dict, List, Optional, Tuple

GENESIS_HASH = "0" * 64

REQUIRED_FIELDS = [
    "seq", "msg_type", "sender", "round", "action_type",
    "parameters", "permission_token", "prev_log_hash", "entry_hash",
]


def canonical_json(obj: Any) -> str:
    """Deterministic JSON serialization used for hashing and for the on-disk
    log lines themselves, so that re-serializing an entry always reproduces
    the same bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_entry_hash(entry: Dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def validate_schema(entry: Dict[str, Any]) -> List[str]:
    """Structural (D1) checks: field presence and basic typing.
    Does NOT check whether the action itself is semantically valid -- that's
    the permission engine's job during replay."""
    errors = []
    for f in REQUIRED_FIELDS:
        if f not in entry:
            errors.append(f"missing field: {f}")
    if errors:
        return errors  # can't type-check fields that aren't there

    if not isinstance(entry["seq"], int) or isinstance(entry["seq"], bool):
        errors.append("seq must be int")
    if not isinstance(entry["msg_type"], str):
        errors.append("msg_type must be str")
    if not isinstance(entry["sender"], str):
        errors.append("sender must be str")
    if not isinstance(entry["round"], int) or isinstance(entry["round"], bool):
        errors.append("round must be int")
    if not isinstance(entry["action_type"], str):
        errors.append("action_type must be str")
    if not isinstance(entry["parameters"], dict):
        errors.append("parameters must be dict")
    if entry["permission_token"] is not None and not isinstance(entry["permission_token"], str):
        errors.append("permission_token must be str or null")
    if not isinstance(entry["prev_log_hash"], str):
        errors.append("prev_log_hash must be str")
    if not isinstance(entry["entry_hash"], str):
        errors.append("entry_hash must be str")

    valid_msg_types = {"action", "rejection", "round_boundary", "malformed_rejection"}
    if isinstance(entry.get("msg_type"), str) and entry["msg_type"] not in valid_msg_types:
        errors.append(f"unknown msg_type: {entry['msg_type']}")

    return errors


class AppendOnlyLog:
    """Thin wrapper around a JSONL file. Every append recomputes prev_log_hash
    from the file itself, so the log is the single source of truth -- there's
    no in-memory chain state to drift from what's on disk."""

    def __init__(self, path: str):
        self.path = path

    def read_all(self) -> List[Dict[str, Any]]:
        entries = []
        try:
            with open(self.path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except FileNotFoundError:
            pass
        return entries

    def last_hash(self) -> str:
        entries = self.read_all()
        return entries[-1]["entry_hash"] if entries else GENESIS_HASH

    def next_seq(self) -> int:
        return len(self.read_all())

    def append(
        self,
        msg_type: str,
        sender: str,
        round_: int,
        action_type: str,
        parameters: Dict[str, Any],
        permission_token: Optional[str],
    ) -> Dict[str, Any]:
        prev_hash = self.last_hash()
        seq = self.next_seq()
        entry = {
            "seq": seq,
            "msg_type": msg_type,
            "sender": sender,
            "round": round_,
            "action_type": action_type,
            "parameters": parameters,
            "permission_token": permission_token,
            "prev_log_hash": prev_hash,
        }
        entry["entry_hash"] = compute_entry_hash(entry)
        with open(self.path, "a") as f:
            f.write(canonical_json(entry) + "\n")
        return entry


def verify_log(path: str) -> Tuple[bool, List[Dict[str, Any]]]:
    """D1 structural verification: schema validity + unbroken, correctly
    computed hash chain. Detects any byte-level tamper. Returns (ok, issues)."""
    issues: List[Dict[str, Any]] = []
    prev_hash = GENESIS_HASH
    expected_seq = 0

    try:
        with open(path, "r") as f:
            lines = [l.rstrip("\n") for l in f if l.strip()]
    except FileNotFoundError:
        return False, [{"type": "D1", "reason": "file_not_found", "path": path}]

    for i, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as e:
            issues.append({"type": "D1", "reason": "invalid_json", "line": i, "error": str(e)})
            continue

        schema_errors = validate_schema(entry)
        if schema_errors:
            issues.append({"type": "D1", "reason": "schema_violation", "line": i, "errors": schema_errors})
            # can't safely chain-check an entry that doesn't have the right shape
            continue

        if entry["seq"] != expected_seq:
            issues.append({
                "type": "D1", "reason": "seq_mismatch", "line": i,
                "expected": expected_seq, "found": entry["seq"],
            })
        expected_seq = entry["seq"] + 1

        if entry["prev_log_hash"] != prev_hash:
            issues.append({
                "type": "D1", "reason": "prev_hash_mismatch", "line": i,
                "expected": prev_hash, "found": entry["prev_log_hash"],
            })

        recomputed = compute_entry_hash(entry)
        if recomputed != entry["entry_hash"]:
            issues.append({
                "type": "D1", "reason": "entry_hash_mismatch", "line": i,
                "expected": recomputed, "found": entry["entry_hash"],
            })

        # Even on mismatch, chain forward using what the (possibly tampered)
        # entry *claims* its hash is -- this is what lets verify detect a
        # single-entry tamper rather than cascading every subsequent line
        # into an unhelpful wall of "prev_hash_mismatch".
        prev_hash = entry["entry_hash"]

    return len(issues) == 0, issues
