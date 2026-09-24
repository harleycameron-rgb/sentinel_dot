"""Bitcoin anchoring of log heads via OpenTimestamps.

An *anchor* is a small JSON record of the log head (next_seq, entry_hash) plus an
OpenTimestamps proof (.ots) committing its SHA-256 into the Bitcoin blockchain. Once the proof
is confirmed (usually a few hours), anyone can show the log reached that state no later than
that block's time, and nobody -- including the key holder -- can later truncate or rewrite
history before that point without it being provable.

This does NOT put log contents on-chain and does not interact with Bitcoin transactions
beyond OpenTimestamps' aggregated commitments (free; one tx per calendar round covers
thousands of timestamps).

Requires:  pip install "sentinel_dot[bitcoin]"   (opentimestamps-client, provides `ots`)
"""
import datetime as _dt
import glob
import hashlib
import json
import os
import shutil
import subprocess
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from . import log as L

try:
    from opentimestamps.core.notary import (BitcoinBlockHeaderAttestation,
                                            PendingAttestation)
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile
except ImportError as _e:  # pragma: no cover
    raise ImportError('Bitcoin anchoring needs: pip install "sentinel_dot[bitcoin]"') from _e

DEFAULT_EXPLORERS = ["https://blockstream.info/api", "https://mempool.space/api"]


class AnchorError(L.LogError):
    pass


def _ots_bin() -> str:
    b = shutil.which("ots")
    if not b:
        raise AnchorError("`ots` not found; pip install opentimestamps-client")
    return b


def _run(args: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run([_ots_bin(), *args], capture_output=True, text=True, timeout=timeout)


def default_anchor_dir(log_path: str) -> str:
    return log_path + ".anchors"


# ---------------------------------------------------------------------------
# create / upgrade
# ---------------------------------------------------------------------------

def write_anchor_record(log_path: str, anchor_dir: Optional[str] = None,
                        now: Optional[str] = None) -> str:
    """Write the head record (canonical JSON) for the log's current state. No network."""
    entries = L.AppendOnlyLog(log_path).read_all()
    if not entries:
        raise AnchorError("log is empty; nothing to anchor")
    last = entries[-1]
    rec = {
        "type": "sentinel_dot-anchor/1",
        "log": os.path.basename(log_path),
        "next_seq": last["seq"] + 1,
        "hash": last["entry_hash"],
        "key_id": last.get("key_id"),
        "created_utc": now or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    d = anchor_dir or default_anchor_dir(log_path)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"anchor-{rec['next_seq']:010d}.json")
    if os.path.exists(path):
        with open(path, "rb") as f:
            if json.loads(f.read())["hash"] != rec["hash"]:
                raise AnchorError(f"{path} exists with a different hash -- log was rewritten?")
        return path
    with open(path, "wb") as f:
        f.write((L.canonical_json(rec) + "\n").encode())
        f.flush(); os.fsync(f.fileno())
    return path


def create_anchor(log_path: str, anchor_dir: Optional[str] = None,
                  calendars: Optional[List[str]] = None) -> Dict[str, Any]:
    """Write the head record and submit it to OpenTimestamps calendars (network).
    Result is a *pending* proof; run upgrade_anchors() later to get the Bitcoin attestation."""
    rec = write_anchor_record(log_path, anchor_dir)
    ots = rec + ".ots"
    if not os.path.exists(ots):
        args = []
        for c in calendars or []:
            args += ["--calendar", c]
        r = _run(["stamp", *args, rec])
        if r.returncode != 0 or not os.path.exists(ots):
            raise AnchorError(f"ots stamp failed: {r.stderr.strip() or r.stdout.strip()}")
    return {"record": rec, "proof": ots, **proof_status(ots)}


def upgrade_anchors(anchor_dir: str) -> List[Dict[str, Any]]:
    """Ask calendars for completed Bitcoin attestations for every pending proof (network)."""
    out = []
    for ots in sorted(glob.glob(os.path.join(anchor_dir, "*.ots"))):
        if proof_status(ots)["bitcoin"]:
            out.append({"proof": ots, "upgraded": False, **proof_status(ots)}); continue
        r = _run(["--no-bitcoin", "upgrade", ots])
        st = proof_status(ots)
        out.append({"proof": ots, "upgraded": bool(st["bitcoin"]),
                    "message": (r.stderr or r.stdout).strip()[-200:], **st})
    return out


# ---------------------------------------------------------------------------
# inspection / verification (verification needs no Bitcoin node)
# ---------------------------------------------------------------------------

def _load_proof(ots_path: str) -> "DetachedTimestampFile":
    with open(ots_path, "rb") as f:
        return DetachedTimestampFile.deserialize(StreamDeserializationContext(f))


def proof_status(ots_path: str) -> Dict[str, Any]:
    d = _load_proof(ots_path)
    pending, btc = [], []
    for msg, att in d.timestamp.all_attestations():
        if isinstance(att, PendingAttestation):
            pending.append(att.uri)
        elif isinstance(att, BitcoinBlockHeaderAttestation):
            btc.append({"height": att.height, "merkle_root": msg[::-1].hex()})
    return {"file_digest": d.file_digest.hex(), "pending": sorted(set(pending)),
            "bitcoin": sorted(btc, key=lambda x: x["height"])}


def _http_get(url: str, timeout: int = 20) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "sentinel_dot"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def explorer_fetch(explorers: Optional[List[str]] = None) -> Callable[[int], Dict[str, Any]]:
    """Returns fetch(height) -> {hash, merkle_root, timestamp} using Esplora-compatible APIs.
    Queries every explorer and requires them to agree (reduces single-explorer trust)."""
    urls = explorers or DEFAULT_EXPLORERS

    def fetch(height: int) -> Dict[str, Any]:
        seen = []
        for base in urls:
            try:
                bh = _http_get(f"{base}/block-height/{height}").decode().strip()
                b = json.loads(_http_get(f"{base}/block/{bh}"))
                seen.append({"hash": b["id"], "merkle_root": b["merkle_root"],
                             "timestamp": b["timestamp"], "source": base})
            except Exception as e:  # noqa: BLE001
                seen.append({"error": f"{base}: {e}"})
        good = [s for s in seen if "error" not in s]
        if not good:
            raise AnchorError(f"no explorer reachable: {seen}")
        if len({(s["hash"], s["merkle_root"]) for s in good}) != 1:
            raise AnchorError(f"explorers disagree at height {height}: {good}")
        return {**good[0], "sources": [s["source"] for s in good]}
    return fetch


def verify_proof(target_path: str, ots_path: Optional[str] = None,
                 fetch: Optional[Callable[[int], Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Verify an OpenTimestamps proof for any file without a Bitcoin node.

    1. sha256(file) must equal the proof's committed digest.
    2. For each Bitcoin attestation, the commitment computed by the proof must equal the
       merkle root of the block at that height, as reported by block explorers.
    Returns the earliest confirmed block (height, hash, time) or status 'pending'.
    Trust note: explorers are trusted for the header; run `ots verify` against your own
    node for trustless verification."""
    ots_path = ots_path or target_path + ".ots"
    with open(target_path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    st = proof_status(ots_path)
    if st["file_digest"] != digest:
        return {"ok": False, "status": "digest_mismatch", "expected": st["file_digest"],
                "found": digest}
    if not st["bitcoin"]:
        return {"ok": False, "status": "pending", "pending": st["pending"]}
    fetch = fetch or explorer_fetch()
    results = []
    for att in st["bitcoin"]:
        blk = fetch(att["height"])
        results.append({"height": att["height"], "block_hash": blk["hash"],
                        "match": blk["merkle_root"] == att["merkle_root"],
                        "block_time_utc": _dt.datetime.fromtimestamp(
                            blk["timestamp"], _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "sources": blk.get("sources")})
    ok = [r for r in results if r["match"]]
    if not ok:
        return {"ok": False, "status": "merkle_root_mismatch", "attestations": results}
    return {"ok": True, "status": "confirmed", **ok[0], "attestations": results}


def check_log_against_anchors(log_path: str, anchor_dir: Optional[str] = None,
                              key: Optional[bytes] = None, verify_key: Any = None,
                              fetch: Optional[Callable[[int], Dict[str, Any]]] = None,
                              require_confirmed: bool = False) -> Dict[str, Any]:
    """Full audit: verify the log's chain/signatures, then check every anchored head is still
    present in the log (detects truncation and rewrites of anchored history), and verify each
    anchor's Bitcoin proof."""
    d = anchor_dir or default_anchor_dir(log_path)
    ok_chain, issues = L.verify_log(log_path, key=key, verify_key=verify_key)
    entries = L.AppendOnlyLog(log_path).read_all() if ok_chain else []
    anchors, problems = [], list(issues)
    for rec_path in sorted(glob.glob(os.path.join(d, "anchor-*.json"))):
        with open(rec_path, "rb") as f:
            rec = json.loads(f.read())
        a = {"record": os.path.basename(rec_path), "next_seq": rec["next_seq"]}
        n = rec["next_seq"]
        if n > len(entries):
            a["in_log"] = False
            problems.append({"reason": "anchored_entries_missing", "anchor": a["record"],
                             "anchored_next_seq": n, "log_next_seq": len(entries)})
        elif entries[n - 1]["entry_hash"] != rec["hash"]:
            a["in_log"] = False
            problems.append({"reason": "anchored_hash_mismatch", "anchor": a["record"]})
        else:
            a["in_log"] = True
        if os.path.exists(rec_path + ".ots"):
            a["proof"] = verify_proof(rec_path, fetch=fetch)
            if a["proof"]["status"] in ("digest_mismatch", "merkle_root_mismatch"):
                problems.append({"reason": "proof_invalid", "anchor": a["record"],
                                 "detail": a["proof"]["status"]})
            elif require_confirmed and a["proof"]["status"] != "confirmed":
                problems.append({"reason": "proof_unconfirmed", "anchor": a["record"]})
        else:
            a["proof"] = {"ok": False, "status": "no_proof"}
            if require_confirmed:
                problems.append({"reason": "proof_missing", "anchor": a["record"]})
        anchors.append(a)
    confirmed = [a for a in anchors if a["proof"].get("status") == "confirmed" and a["in_log"]]
    latest = max(confirmed, key=lambda a: a["next_seq"]) if confirmed else None
    return {"ok": not problems, "problems": problems, "anchors": anchors,
            "bitcoin_proven_through_seq": latest["next_seq"] - 1 if latest else None,
            "proven_no_later_than": latest["proof"]["block_time_utc"] if latest else None}
