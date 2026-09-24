"""Ed25519 auditor-mode tests: writer signs with private key; auditor verifies with public key
only and cannot forge."""
import json, os, stat, pytest
from sentinel_dot import log as L, AgentRecorder
from sentinel_dot.signing import Ed25519Signer, Ed25519Verifier
from sentinel_dot.cli import main
from legacy import legacy_log as OLD

@pytest.fixture
def signer(): return Ed25519Signer.generate()
@pytest.fixture
def auditor(signer): return Ed25519Verifier.from_pem(signer.public_pem())  # public key only
@pytest.fixture
def p(tmp_path): return str(tmp_path / "log.jsonl")

def fill(path, signer, n=4):
    lg = L.AppendOnlyLog(path, signer=signer)
    for i in range(n): lg.append("action", "agent", 0, "move", {"x": i}, None)
    return lg

def lines(p): return open(p, "rb").read().splitlines()
def write_lines(p, ls): open(p, "wb").write(b"".join(l + b"\n" for l in ls))
def reasons(issues): return {i["reason"] for i in issues}

# --- happy path ---
def test_auditor_verifies_with_public_key_only(p, signer, auditor):
    lg = fill(p, signer)
    ok, issues = L.verify_log(p, verify_key=auditor, expected_head=lg.head())
    assert ok, issues
    e = json.loads(lines(p)[0])
    assert len(e["signature"]) == 128 and e["key_id"] == signer.key_id

def test_signed_log_still_verifies_as_plain_chain(p, signer):
    fill(p, signer)
    assert L.verify_log(p)[0]  # structural check without any key works too

def test_signature_excluded_from_entry_hash(p, signer, tmp_path):
    fill(p, signer, 1); plain = str(tmp_path / "plain.jsonl")
    L.AppendOnlyLog(plain).append("action", "agent", 0, "move", {"x": 0}, None)
    assert json.loads(lines(p)[0])["entry_hash"] == json.loads(lines(plain)[0])["entry_hash"]

def test_key_id_stable_across_pem_roundtrip(signer):
    assert Ed25519Signer.from_pem(signer.private_pem()).key_id == signer.key_id
    assert Ed25519Verifier.from_pem(signer.public_pem()).key_id == signer.key_id

def test_encrypted_private_key(signer):
    pem = signer.private_pem(b"pw")
    assert b"ENCRYPTED" in pem
    assert Ed25519Signer.from_pem(pem, b"pw").key_id == signer.key_id
    with pytest.raises(Exception): Ed25519Signer.from_pem(pem, b"wrong")

def test_agent_recorder_signing(p, signer, auditor):
    rec = AgentRecorder(p, "planner", signer=signer)
    @rec.tool
    def f(x): return x * 2
    f(3); rec.next_round()
    assert L.verify_log(p, verify_key=auditor, expected_head=rec.head())[0]

# --- auditor cannot be fooled / cannot forge ---
def test_content_tamper_detected(p, signer, auditor):
    fill(p, signer); ls = lines(p); e = json.loads(ls[1]); e["parameters"]["x"] = 99
    ls[1] = L.canonical_json(e).encode(); write_lines(p, ls)
    assert "entry_hash_mismatch" in reasons(L.verify_log(p, verify_key=auditor)[1])

def test_rehash_without_private_key_detected(p, signer, auditor):
    """Attacker edits content AND recomputes SHA-256 hashes/chain, keeping old signatures."""
    fill(p, signer); es = [json.loads(l) for l in lines(p)]
    es[1]["parameters"]["x"] = 99; prev = es[0]["entry_hash"]
    for e in es[1:]:
        e["prev_log_hash"] = prev; e["entry_hash"] = L.compute_entry_hash(e); prev = e["entry_hash"]
    write_lines(p, [L.canonical_json(e).encode() for e in es])
    ok, issues = L.verify_log(p, verify_key=auditor)
    assert not ok and {i["line"] for i in issues if i["reason"] == "signature_invalid"} == {1, 2, 3}

def test_forged_with_attackers_own_key_detected(p, signer, auditor):
    fill(p, Ed25519Signer.generate())                   # attacker's key
    assert "unknown_key_id" in reasons(L.verify_log(p, verify_key=auditor)[1])

def test_spoofed_key_id_detected(p, signer, auditor):
    evil = Ed25519Signer.generate(); fill(p, evil)
    ls = [json.loads(l) for l in lines(p)]
    for e in ls: e["key_id"] = signer.key_id           # claim to be the real key
    write_lines(p, [L.canonical_json(e).encode() for e in ls])
    assert "signature_invalid" in reasons(L.verify_log(p, verify_key=auditor)[1])

def test_stripped_signature_detected(p, signer, auditor):
    fill(p, signer); ls = [json.loads(l) for l in lines(p)]
    del ls[2]["signature"]; del ls[2]["key_id"]
    write_lines(p, [L.canonical_json(e).encode() for e in ls])
    issues = L.verify_log(p, verify_key=auditor)[1]
    assert [i["line"] for i in issues if i["reason"] == "missing_signature"] == [2]

def test_unsigned_log_fails_auditor(p, auditor):
    L.AppendOnlyLog(p).append("action", "a", 0, "m", {}, None)
    assert "missing_signature" in reasons(L.verify_log(p, verify_key=auditor)[1])

def test_truncation_needs_anchor(p, signer, auditor):
    head = fill(p, signer).head(); write_lines(p, lines(p)[:2])
    assert L.verify_log(p, verify_key=auditor)[0]
    assert "head_mismatch" in reasons(L.verify_log(p, verify_key=auditor, expected_head=head)[1])

def test_malformed_signature_fields(p, signer):
    fill(p, signer, 1); e = json.loads(lines(p)[0])
    for bad in ({"signature": "zz"}, {"key_id": "rsa:1"}):
        x = dict(e, **bad); write_lines(p, [L.canonical_json(x).encode()])
        assert "schema_violation" in reasons(L.verify_log(p)[1])
    x = dict(e); del x["key_id"]; write_lines(p, [L.canonical_json(x).encode()])
    assert "schema_violation" in reasons(L.verify_log(p)[1])

# --- mode exclusivity ---
def test_hmac_and_signer_together_refused(p, signer):
    with pytest.raises(L.LogError): L.AppendOnlyLog(p, key=b"k" * 32, signer=signer)

def test_verify_with_both_refused(p, signer, auditor):
    fill(p, signer)
    with pytest.raises(L.LogError): L.verify_log(p, key=b"k" * 32, verify_key=auditor)

# --- migration + key rotation ---
def test_migrate_legacy_to_signed(tmp_path, signer, auditor):
    src, dst = str(tmp_path / "old"), str(tmp_path / "new")
    o = OLD.AppendOnlyLog(src)
    for i in range(3): o.append("action", "a", 0, "m", {"v": i / 2}, None)
    rep = L.migrate_legacy_log(src, dst, signer=signer, expected_legacy_head=o.last_hash())
    assert rep["signing_key_id"] == signer.key_id
    assert L.verify_log(dst, verify_key=auditor, expected_head=tuple(rep["new_head"]))[0]

def test_rotation_old_key_rejected_for_new_segment(p, signer, auditor):
    fill(p, Ed25519Signer.generate())                   # next segment signed by rotated key
    assert not L.verify_log(p, verify_key=auditor)[0]   # old public key must not validate it

# --- CLI ---
def test_cli_ed25519_flow(tmp_path, capsys):
    pre = str(tmp_path / "writer")
    assert main(["keygen", "--ed25519", pre]) == 0
    info = json.loads(capsys.readouterr().out)
    assert stat.S_IMODE(os.stat(info["private"]).st_mode) == 0o600
    assert main(["keygen", "--ed25519", pre]) == 2     # refuses to overwrite
    lg = L.AppendOnlyLog(str(tmp_path / "l"), signer=Ed25519Signer.from_file(info["private"]))
    lg.append("action", "a", 0, "m", {}, None); seq, h = lg.head()
    assert main(["verify", lg.path, "--pubkey", info["public"],
                 "--expect-seq", str(seq), "--expect-hash", h]) == 0
    other = str(tmp_path / "other"); main(["keygen", "--ed25519", other]); capsys.readouterr()
    assert main(["verify", lg.path, "--pubkey", other + ".pub"]) == 1

def test_cli_migrate_signed(tmp_path, capsys):
    src, dst, pre = str(tmp_path / "old"), str(tmp_path / "new"), str(tmp_path / "w")
    OLD.AppendOnlyLog(src).append("action", "a", 0, "m", {}, None)
    main(["keygen", "--ed25519", pre]); capsys.readouterr()
    assert main(["migrate", src, dst, "--signing-key", pre + ".key"]) == 0
    capsys.readouterr()
    assert main(["verify", dst, "--pubkey", pre + ".pub"]) == 0
