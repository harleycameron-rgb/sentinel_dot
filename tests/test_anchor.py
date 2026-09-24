"""Bitcoin anchoring tests. Offline tests build synthetic OpenTimestamps proofs and a fake
block explorer; tests marked `network` hit real calendars/explorers (run: pytest -m network)."""
import hashlib, io, json, os, shutil, urllib.request, pytest
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256, OpPrepend
from opentimestamps.core.serialize import StreamSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
from sentinel_dot import log as L, AgentRecorder
from sentinel_dot import anchor as A
from sentinel_dot.signing import Ed25519Signer
from sentinel_dot.cli import main

def make_proof(path, height=800000, pending_only=False):
    """Synthetic .ots: sha256(file) -> append/prepend/sha256 -> Bitcoin attestation.
    Returns the merkle root (display hex) a real block would need to have."""
    digest = hashlib.sha256(open(path, "rb").read()).digest()
    d = DetachedTimestampFile(OpSHA256(), Timestamp(digest))
    t = d.timestamp.ops.add(OpAppend(b"\x01" * 16)).ops.add(OpSHA256())
    if pending_only:
        t.attestations.add(PendingAttestation("https://alice.btc.calendar.opentimestamps.org"))
        root = None
    else:
        t = t.ops.add(OpPrepend(b"\x02" * 32)).ops.add(OpSHA256())
        t.attestations.add(BitcoinBlockHeaderAttestation(height)); root = t.msg[::-1].hex()
    buf = io.BytesIO(); d.serialize(StreamSerializationContext(buf))
    open(path + ".ots", "wb").write(buf.getvalue())
    return root

def fake_fetch(roots):  # height -> merkle root
    return lambda h: {"hash": f"{h:064x}", "merkle_root": roots[h], "timestamp": 1700000000,
                      "sources": ["fake"]}

@pytest.fixture
def signer(): return Ed25519Signer.generate()

@pytest.fixture
def logp(tmp_path, signer):
    p = str(tmp_path / "agent.jsonl"); r = AgentRecorder(p, "planner", signer=signer)
    for i in range(3): r.action("tool:x", {"i": i})
    return p

# --- records ---
def test_record_contents(logp, signer):
    rec = A.write_anchor_record(logp, now="2026-09-25T00:00:00Z")
    r = json.loads(open(rec).read()); last = L.AppendOnlyLog(logp).read_all()[-1]
    assert r == {"type": "sentinel_dot-anchor/1", "log": "agent.jsonl", "next_seq": 3,
                 "hash": last["entry_hash"], "key_id": signer.key_id,
                 "created_utc": "2026-09-25T00:00:00Z"}
    assert rec.endswith("anchor-0000000003.json")

def test_record_idempotent_and_detects_rewrite(logp, tmp_path):
    rec = A.write_anchor_record(logp); assert A.write_anchor_record(logp) == rec
    os.remove(logp); r = AgentRecorder(logp, "evil")
    for i in range(3): r.action("tool:y", {})
    with pytest.raises(A.AnchorError, match="different hash"):
        A.write_anchor_record(logp)

def test_empty_log_refused(tmp_path):
    p = str(tmp_path / "e.jsonl"); open(p, "w").close()
    with pytest.raises(A.AnchorError): A.write_anchor_record(p)

# --- proof verification ---
def test_confirmed_proof(logp):
    rec = A.write_anchor_record(logp); root = make_proof(rec, 812345)
    r = A.verify_proof(rec, fetch=fake_fetch({812345: root}))
    assert r["ok"] and r["status"] == "confirmed" and r["height"] == 812345

def test_pending_proof(logp):
    rec = A.write_anchor_record(logp); make_proof(rec, pending_only=True)
    r = A.verify_proof(rec)
    assert not r["ok"] and r["status"] == "pending" and r["pending"]

def test_record_edited_after_stamping(logp):
    rec = A.write_anchor_record(logp); root = make_proof(rec)
    open(rec, "ab").write(b" ")
    assert A.verify_proof(rec, fetch=fake_fetch({800000: root}))["status"] == "digest_mismatch"

def test_wrong_block_merkle_root(logp):
    rec = A.write_anchor_record(logp); make_proof(rec)
    r = A.verify_proof(rec, fetch=fake_fetch({800000: "00" * 32}))
    assert not r["ok"] and r["status"] == "merkle_root_mismatch"

def test_explorers_must_agree(monkeypatch):
    def fake_get(url, timeout=20):
        if "block-height" in url: return b"abc"
        root = "11" * 32 if "one" in url else "22" * 32
        return json.dumps({"id": "abc", "merkle_root": root, "timestamp": 1}).encode()
    monkeypatch.setattr(A, "_http_get", fake_get)
    with pytest.raises(A.AnchorError, match="disagree"):
        A.explorer_fetch(["https://one", "https://two"])(1)

# --- full audit ---
def test_audit_clean(logp, signer):
    rec = A.write_anchor_record(logp); root = make_proof(rec, 900000)
    r = A.check_log_against_anchors(logp, verify_key=signer.verifier,
                                    fetch=fake_fetch({900000: root}), require_confirmed=True)
    assert r["ok"], r["problems"]
    assert r["bitcoin_proven_through_seq"] == 2

def test_audit_detects_truncation_below_anchor(logp, signer):
    rec = A.write_anchor_record(logp); root = make_proof(rec)
    ls = open(logp, "rb").read().splitlines(); open(logp, "wb").write(ls[0] + b"\n")
    r = A.check_log_against_anchors(logp, verify_key=signer.verifier,
                                    fetch=fake_fetch({800000: root}))
    assert not r["ok"] and r["problems"][0]["reason"] == "anchored_entries_missing"

def test_audit_detects_resigned_rewrite(logp, signer, tmp_path):
    """Key holder rewrites history and re-signs it validly -- only the anchor catches it."""
    rec = A.write_anchor_record(logp); root = make_proof(rec)
    os.remove(logp); r = AgentRecorder(logp, "planner", signer=signer)
    for i in range(3): r.action("tool:x", {"i": i * 10})
    assert L.verify_log(logp, verify_key=signer.verifier)[0]   # signatures alone: fooled
    res = A.check_log_against_anchors(logp, verify_key=signer.verifier,
                                      fetch=fake_fetch({800000: root}))
    assert not res["ok"] and res["problems"][0]["reason"] == "anchored_hash_mismatch"

def test_audit_appends_after_anchor_ok(logp, signer):
    rec = A.write_anchor_record(logp); root = make_proof(rec)
    AgentRecorder(logp, "planner", signer=signer, round_=1).action("tool:z", {})
    r = A.check_log_against_anchors(logp, verify_key=signer.verifier, fetch=fake_fetch({800000: root}))
    assert r["ok"] and r["bitcoin_proven_through_seq"] == 2

def test_audit_require_confirmed(logp, signer):
    rec = A.write_anchor_record(logp); make_proof(rec, pending_only=True)
    r = A.check_log_against_anchors(logp, verify_key=signer.verifier, require_confirmed=True)
    assert not r["ok"] and r["problems"][0]["reason"] == "proof_unconfirmed"
    assert A.check_log_against_anchors(logp, verify_key=signer.verifier)["ok"]

def test_cli_status_and_verify_proof(logp, capsys):
    rec = A.write_anchor_record(logp); make_proof(rec, pending_only=True)
    assert main(["anchor", "status", logp]) == 0
    assert "pending" in capsys.readouterr().out
    assert main(["anchor", "verify-proof", rec]) == 1   # pending -> not ok

# --- live network ---
EX = "https://raw.githubusercontent.com/opentimestamps/opentimestamps-client/master/examples/"

@pytest.mark.network
def test_live_verify_real_bitcoin_proof(tmp_path):
    for f in ("hello-world.txt", "hello-world.txt.ots"):
        urllib.request.urlretrieve(EX + f, str(tmp_path / f))
    r = A.verify_proof(str(tmp_path / "hello-world.txt"))
    assert r["ok"] and r["height"] == 358391 and r["block_time_utc"].startswith("2015-05-28")

@pytest.mark.network
@pytest.mark.skipif(not shutil.which("ots"), reason="ots not installed")
def test_live_stamp(logp):
    r = A.create_anchor(logp)
    assert os.path.exists(r["proof"]) and r["pending"] and not r["bitcoin"]
