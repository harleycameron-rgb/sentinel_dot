"""
Hash-chained, append-only JSONL log (hardened).

Each entry:
    seq, msg_type, sender, round, action_type, parameters,
    permission_token, prev_log_hash, entry_hash

entry_hash = HMAC-SHA256(key, canonical_json(entry_without_entry_hash))  if key given
           = SHA256(canonical_json(entry_without_entry_hash))            otherwise
prev_log_hash = previous entry's entry_hash (GENESIS_HASH for the first entry)

Guarantees:
  * byte-level tamper evidence per entry (hash) and ordering (chain)
  * forgery resistance when a secret key is used (unkeyed mode only detects accidents)
  * truncation detection when verify_log() is given an externally anchored head
  * strict schema: no unknown fields, no NaN/Infinity, no floats in parameters
  * crash safety: exclusive lock, fsync, torn trailing line detected and refused/repaired

Semantic validity of actions remains the permission engine's job.
"""

import hashlib
import hmac
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    import fcntl  # POSIX
except ImportError:  # pragma: no cover
    fcntl = None

GENESIS_HASH = "0" * 64
REQUIRED_FIELDS = [
    "seq", "msg_type", "sender", "round", "action_type",
    "parameters", "permission_token", "prev_log_hash", "entry_hash",
]
VALID_MSG_TYPES = {"action", "rejection", "round_boundary", "malformed_rejection"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
# Optional fields: excluded from entry_hash (like entry_hash itself).
#   signature: Ed25519 signature (hex) over the entry_hash ASCII string
#   key_id:    identifier of the signing public key ("ed25519:<16 hex>")
OPTIONAL_FIELDS = ["signature", "key_id"]
_UNHASHED = {"entry_hash", "signature", "key_id"}


class LogError(Exception):
    pass


class TornWriteError(LogError):
    """Last line of the file is incomplete (crash mid-write)."""


def canonical_json(obj: Any) -> str:
    """Deterministic serialization. Rejects NaN/Infinity so output is always valid JSON."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def compute_entry_hash(entry: Dict[str, Any], key: Optional[bytes] = None) -> str:
    body = canonical_json({k: v for k, v in entry.items() if k not in _UNHASHED}).encode("utf-8")
    if key:
        return hmac.new(key, body, hashlib.sha256).hexdigest()
    return hashlib.sha256(body).hexdigest()


def _check_json_value(v: Any, path: str, errors: List[str]) -> None:
    """Parameters may contain only str, int, bool, None, list, dict (str keys). Floats banned
    so hashes are identical across languages/runtimes."""
    if isinstance(v, bool) or v is None or isinstance(v, (str, int)):
        return
    if isinstance(v, float):
        errors.append(f"{path}: floats not allowed (encode as string or scaled int)")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            _check_json_value(x, f"{path}[{i}]", errors)
    elif isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str):
                errors.append(f"{path}: non-str key {k!r}")
            _check_json_value(x, f"{path}.{k}", errors)
    else:
        errors.append(f"{path}: unsupported type {type(v).__name__}")


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def validate_schema(entry: Dict[str, Any]) -> List[str]:
    """Structural (D1) checks."""
    if not isinstance(entry, dict):
        return ["entry must be object"]
    errors = [f"missing field: {f}" for f in REQUIRED_FIELDS if f not in entry]
    errors += [f"unknown field: {f}" for f in entry
               if f not in REQUIRED_FIELDS and f not in OPTIONAL_FIELDS]
    if ("signature" in entry) != ("key_id" in entry):
        errors.append("signature and key_id must appear together")
    if "signature" in entry and (not isinstance(entry["signature"], str)
                                 or not _HEX128.match(entry["signature"])):
        errors.append("signature must be 128 lowercase hex chars")
    if "key_id" in entry and (not isinstance(entry["key_id"], str)
                              or not re.match(r"^ed25519:[0-9a-f]{16}$", entry["key_id"])):
        errors.append("key_id must be 'ed25519:<16 hex>'")
    if any(e.startswith("missing") for e in errors):
        return errors

    if not _is_int(entry["seq"]) or entry["seq"] < 0:
        errors.append("seq must be non-negative int")
    if not _is_int(entry["round"]) or entry["round"] < 0:
        errors.append("round must be non-negative int")
    for f in ("msg_type", "sender", "action_type"):
        if not isinstance(entry[f], str) or not entry[f]:
            errors.append(f"{f} must be non-empty str")
    if not isinstance(entry["parameters"], dict):
        errors.append("parameters must be dict")
    else:
        _check_json_value(entry["parameters"], "parameters", errors)
    if entry["permission_token"] is not None and not isinstance(entry["permission_token"], str):
        errors.append("permission_token must be str or null")
    for f in ("prev_log_hash", "entry_hash"):
        if not isinstance(entry[f], str) or not _HEX64.match(entry[f]):
            errors.append(f"{f} must be 64 lowercase hex chars")
    if isinstance(entry["msg_type"], str) and entry["msg_type"] not in VALID_MSG_TYPES:
        errors.append(f"unknown msg_type: {entry['msg_type']}")
    return errors


class _Lock:
    def __init__(self, f):
        self.f = f

    def __enter__(self):
        if fcntl:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)

    def __exit__(self, *a):
        if fcntl:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)


def _read_last_line(f) -> Tuple[bytes, bool]:
    """Return (last line without trailing newline, is_torn). Reads backwards in chunks,
    so cost is O(last line length), not O(file size)."""
    f.seek(0, os.SEEK_END)
    size = f.tell()
    if size == 0:
        return b"", False
    f.seek(size - 1)
    torn = f.read(1) != b"\n"
    end = size if torn else size - 1
    pos, buf = end, b""
    while pos > 0:
        step = min(4096, pos)
        pos -= step
        f.seek(pos)
        buf = f.read(step) + buf
        idx = buf.rfind(b"\n", 0, end - pos)
        if idx != -1:
            return buf[idx + 1:end - pos], torn
    return buf[:end], torn


class AppendOnlyLog:
    """JSONL file wrapper. The file is the source of truth; each append takes an exclusive
    lock, reads only the last line to get (seq, hash), writes, flushes and fsyncs."""

    def __init__(self, path: str, key: Optional[bytes] = None, repair_torn_tail: bool = False,
                 signer: Any = None):
        """Choose ONE authentication mode:
          key=<bytes>     HMAC-SHA256 entry hashes (writer and verifier share the secret)
          signer=<Signer> plain SHA-256 entry hashes + Ed25519 signature per entry; auditors
                          verify with the public key only and cannot forge
          neither         plain SHA-256 (accident detection only)"""
        if key is not None and signer is not None:
            raise LogError("use either key (HMAC) or signer (Ed25519), not both: auditors "
                           "without the HMAC key could not bind signatures to content")
        self.path = path
        self.key = key
        self.signer = signer
        self.repair_torn_tail = repair_torn_tail

    def read_all(self) -> List[Dict[str, Any]]:
        """Parse all complete lines. Raises TornWriteError on an incomplete final line and
        LogError on any other unparsable line (use verify_log for diagnostics)."""
        entries = []
        try:
            with open(self.path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return entries
        if data and not data.endswith(b"\n"):
            raise TornWriteError(f"{self.path}: incomplete final line")
        for i, line in enumerate(data.split(b"\n")):
            if line.strip():
                try:
                    entries.append(json.loads(line.decode("utf-8")))
                except (ValueError, UnicodeDecodeError) as e:
                    raise LogError(f"line {i}: {e}") from e
        return entries

    def head(self) -> Tuple[int, str]:
        """(next_seq, last_hash). Anchor this externally to detect truncation."""
        entries = self.read_all()
        if not entries:
            return 0, GENESIS_HASH
        return entries[-1]["seq"] + 1, entries[-1]["entry_hash"]

    def _tail_state(self, f) -> Tuple[int, str]:
        line, torn = _read_last_line(f)
        if torn:
            if not self.repair_torn_tail:
                raise TornWriteError(f"{self.path}: incomplete final line; "
                                     "re-open with repair_torn_tail=True to truncate it")
            f.seek(0, os.SEEK_END)
            f.truncate(f.tell() - len(line))
            f.flush()
            os.fsync(f.fileno())
            line, torn = _read_last_line(f)
        if not line.strip():
            return 0, GENESIS_HASH
        try:
            last = json.loads(line.decode("utf-8"))
            return last["seq"] + 1, last["entry_hash"]
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as e:
            raise LogError(f"{self.path}: last line unreadable, refusing to append") from e

    def append(self, msg_type: str, sender: str, round_: int, action_type: str,
               parameters: Dict[str, Any], permission_token: Optional[str]) -> Dict[str, Any]:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        with os.fdopen(fd, "r+b") as f, _Lock(f):
            seq, prev_hash = self._tail_state(f)
            entry = {
                "seq": seq, "msg_type": msg_type, "sender": sender, "round": round_,
                "action_type": action_type, "parameters": parameters,
                "permission_token": permission_token, "prev_log_hash": prev_hash,
            }
            entry["entry_hash"] = compute_entry_hash(entry, self.key)
            _sign(entry, self.signer)
            errs = validate_schema(entry)
            if errs:
                raise LogError(f"refusing to append invalid entry: {errs}")
            f.seek(0, os.SEEK_END)
            f.write((canonical_json(entry) + "\n").encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        return entry


def _sign(entry: Dict[str, Any], signer: Any) -> None:
    if signer is not None:
        entry["signature"] = signer.sign(entry["entry_hash"])
        entry["key_id"] = signer.key_id


def verify_log(path: str, key: Optional[bytes] = None,
               expected_head: Optional[Tuple[int, str]] = None,
               verify_key: Any = None
               ) -> Tuple[bool, List[Dict[str, Any]]]:
    """D1 verification: schema, seq continuity, hash chain, (keyed) entry hashes, and
    optionally that the log ends exactly at an externally anchored head (next_seq, hash).

    Auditors of an Ed25519-signed log pass verify_key=Ed25519Verifier and no key."""
    if key is not None and verify_key is not None:
        raise LogError("pass either key (HMAC) or verify_key (Ed25519), not both")
    issues: List[Dict[str, Any]] = []
    prev_hash, expected_seq = GENESIS_HASH, 0

    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return False, [{"type": "D1", "reason": "file_not_found", "path": path}]

    if data and not data.endswith(b"\n"):
        issues.append({"type": "D1", "reason": "torn_final_line"})
    raw_lines = data.split(b"\n")
    if data.endswith(b"\n"):
        raw_lines = raw_lines[:-1]

    for i, raw in enumerate(raw_lines):
        if not raw.strip():
            issues.append({"type": "D1", "reason": "blank_line", "line": i})
            continue
        try:
            entry = json.loads(raw.decode("utf-8"),
                               parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
        except (ValueError, UnicodeDecodeError) as e:
            issues.append({"type": "D1", "reason": "invalid_json", "line": i, "error": str(e)})
            expected_seq += 1
            continue

        schema_errors = validate_schema(entry)
        if schema_errors:
            issues.append({"type": "D1", "reason": "schema_violation", "line": i,
                           "errors": schema_errors})
            expected_seq += 1
            if isinstance(entry, dict) and isinstance(entry.get("entry_hash"), str):
                prev_hash = entry["entry_hash"]
            continue

        if canonical_json(entry).encode("utf-8") != raw.rstrip(b"\r"):
            issues.append({"type": "D1", "reason": "non_canonical_encoding", "line": i})

        if entry["seq"] != expected_seq:
            issues.append({"type": "D1", "reason": "seq_mismatch", "line": i,
                           "expected": expected_seq, "found": entry["seq"]})
        expected_seq += 1  # position-based: tampered seq can't resync the counter

        if entry["prev_log_hash"] != prev_hash:
            issues.append({"type": "D1", "reason": "prev_hash_mismatch", "line": i,
                           "expected": prev_hash, "found": entry["prev_log_hash"]})

        if verify_key is not None:
            if "signature" not in entry:
                issues.append({"type": "D1", "reason": "missing_signature", "line": i})
            elif entry["key_id"] != verify_key.key_id:
                issues.append({"type": "D1", "reason": "unknown_key_id", "line": i,
                               "expected": verify_key.key_id, "found": entry["key_id"]})
            elif not verify_key.verify(entry["entry_hash"], entry["signature"]):
                issues.append({"type": "D1", "reason": "signature_invalid", "line": i})

        recomputed = compute_entry_hash(entry, key)
        if not hmac.compare_digest(recomputed, entry["entry_hash"]):
            issues.append({"type": "D1", "reason": "entry_hash_mismatch", "line": i,
                           "expected": recomputed, "found": entry["entry_hash"]})

        # chain forward on the claimed hash so one tamper doesn't cascade
        prev_hash = entry["entry_hash"]

    if expected_head is not None:
        exp_seq, exp_hash = expected_head
        if (expected_seq, prev_hash) != (exp_seq, exp_hash):
            issues.append({"type": "D1", "reason": "head_mismatch",
                           "expected": {"next_seq": exp_seq, "hash": exp_hash},
                           "found": {"next_seq": expected_seq, "hash": prev_hash}})

    return len(issues) == 0, issues


# ---------------------------------------------------------------------------
# Legacy migration
# ---------------------------------------------------------------------------

def _legacy_sha256(entry: Dict[str, Any]) -> str:
    """Hash exactly as the original log.py did (allow_nan default True)."""
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode("utf-8")).hexdigest()


def _convert_floats(v: Any, path: str, converted: List[str]) -> Any:
    """Floats -> exact repr strings (NaN/Infinity -> 'NaN'/'Infinity'). Recorded in report."""
    if isinstance(v, float):
        converted.append(path)
        return repr(v) if v == v and v not in (float("inf"), float("-inf")) else \
            ("NaN" if v != v else ("Infinity" if v > 0 else "-Infinity"))
    if isinstance(v, list):
        return [_convert_floats(x, f"{path}[{i}]", converted) for i, x in enumerate(v)]
    if isinstance(v, dict):
        return {k: _convert_floats(x, f"{path}.{k}", converted) for k, x in v.items()}
    return v


def migrate_legacy_log(src: str, dst: str, key: Optional[bytes] = None,
                       expected_legacy_head: Optional[str] = None,
                       convert_floats: bool = True, signer: Any = None) -> Dict[str, Any]:
    """Re-chain a log written by the original (unkeyed, lax) log.py into the hardened format.

    1. Verifies the legacy chain with legacy rules (plain SHA-256, NaN tolerated,
       extra fields hashed as-is). Any break aborts -- we never re-sign tampered data.
    2. Optionally checks the legacy final hash against an external anchor.
    3. Converts floats to exact strings (or aborts if convert_floats=False), rejects
       unknown fields, re-validates under the strict schema, re-chains with `key`.
    4. Writes dst atomically (temp file + fsync + rename). src is never modified.

    Returns a report: counts, legacy head, new head, converted float paths.
    """
    if key is not None and signer is not None:
        raise LogError("use either key (HMAC) or signer (Ed25519), not both")
    if os.path.abspath(src) == os.path.abspath(dst):
        raise LogError("dst must differ from src")
    with open(src, "rb") as f:
        data = f.read()
    if data and not data.endswith(b"\n"):
        raise TornWriteError(f"{src}: incomplete final line; repair before migrating")

    legacy, prev = [], GENESIS_HASH
    for i, raw in enumerate(l for l in data.split(b"\n") if l.strip()):
        try:
            e = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as ex:
            raise LogError(f"legacy line {i}: invalid JSON: {ex}") from ex
        if not isinstance(e, dict) or any(k not in e for k in REQUIRED_FIELDS):
            raise LogError(f"legacy line {i}: missing required fields")
        if e["seq"] != i:
            raise LogError(f"legacy line {i}: seq {e['seq']} != {i}")
        if e["prev_log_hash"] != prev:
            raise LogError(f"legacy line {i}: broken chain")
        if _legacy_sha256(e) != e["entry_hash"]:
            raise LogError(f"legacy line {i}: entry hash mismatch (tampered?)")
        prev = e["entry_hash"]
        legacy.append(e)

    if expected_legacy_head is not None and prev != expected_legacy_head:
        raise LogError("legacy head mismatch: log truncated or not the anchored log")

    converted: List[str] = []
    out, prev_new = [], GENESIS_HASH
    for i, e in enumerate(legacy):
        extra = [k for k in e if k not in REQUIRED_FIELDS]
        if extra:
            raise LogError(f"legacy line {i}: unknown fields {extra} cannot be migrated")
        params = e["parameters"]
        if convert_floats:
            params = _convert_floats(params, f"line{i}.parameters", converted)
        n = {k: e[k] for k in REQUIRED_FIELDS if k != "entry_hash"}
        n["parameters"], n["prev_log_hash"] = params, prev_new
        n["entry_hash"] = compute_entry_hash(n, key)
        _sign(n, signer)
        errs = validate_schema(n)
        if errs:
            raise LogError(f"legacy line {i}: fails strict schema after migration: {errs}")
        prev_new = n["entry_hash"]
        out.append(n)

    tmp = dst + ".tmp"
    with open(tmp, "wb") as f:
        for n in out:
            f.write((canonical_json(n) + "\n").encode("utf-8"))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, dst)

    return {"entries": len(out), "legacy_head": prev,
            "new_head": (len(out), prev_new), "keyed": bool(key),
            "signing_key_id": signer.key_id if signer else None,
            "converted_floats": converted}
