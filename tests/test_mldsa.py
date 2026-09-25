"""Post-quantum ML-DSA (FIPS 204) and hybrid Ed25519+ML-DSA-65 signing tests."""
import json, os, stat, pytest
from sentinel_dot import log as L, AgentRecorder
from sentinel_dot import signing as G
from sentinel_dot.cli import main
from legacy import legacy_log as OLD

pytestmark = pytest.mark.skipif(not G.mldsa_available(), reason="ML-DSA needs cryptography>=48")
ALGS = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87", G.HYBRID]

def lines(p): return open(p, "rb").read().splitlines()
def write_lines(p, ls): open(p, "wb").write(b"".join(l + b"\n" for l in ls))
def reasons(issues): return {i["reason"] for i in issues}
def fill(p, s, n=3):
    lg = L.AppendOnlyLog(p, signer=s)
    for i in range(n): lg.append("action", "agent", 0, "move", {"x": i}, None)
    return lg

@pytest.fixture(params=ALGS)
def alg(request): return request.param

@pytest.fixture
def signer(alg): return G.generate(alg)

@pytest.fixture
def auditor(signer): return G.load_verifier_pem(signer.public_pem())

@pytest.fixture
def p(tmp_path): return str(tmp_path / "log.jsonl")

# --- round trip per algorithm ---
def test_sign_verify_roundtrip(p, signer, auditor, alg):
    lg = fill(p, signer)
    ok, issues = L.verify_log(p, verify_key=auditor, expected_head=lg.head())
    assert ok, issues
    e = json.loads(lines(p)[0])
    assert e["key_id"].startswith(alg + ":")
    assert len(e["signature"]) == 2 * G.SIG_BYTES[alg] == L.SIGNATURE_HEX_LEN[alg]

def test_key_ids_and_algs_survive_pem(signer, alg):
    s2 = G.load_signer_pem(signer.private_pem())
    v2 = G.load_verifier_pem(signer.public_pem())
    assert s2.key_id == v2.key_id == signer.key_id and s2.alg == v2.alg == alg

def test_encrypted_private_key(signer):
    pem = signer.private_pem(b"pw")
    assert pem.count(b"ENCRYPTED") >= 1
    assert G.load_signer_pem(pem, b"pw").key_id == signer.key_id
    with pytest.raises(Exception): G.load_signer_pem(pem, b"wrong")

def test_agent_recorder(p, signer, auditor):
    rec = AgentRecorder(p, "planner", signer=signer)
    @rec.tool
    def f(x): return x + 1
    f(1); rec.next_round()
    assert L.verify_log(p, verify_key=auditor, expected_head=rec.head())[0]

def test_long_signed_lines_append_correctly(p, alg):
    """ML-DSA-87 lines are ~9.5 KB; tail reading must cross 4 KB chunk boundaries."""
    s = G.generate(alg); lg = fill(p, s, 5)
    assert lg.head()[0] == 5 and L.verify_log(p, verify_key=s.verifier)[0]

# --- attacks ---
def test_content_tamper(p, signer, auditor):
    fill(p, signer); ls = lines(p); e = json.loads(ls[1]); e["parameters"]["x"] = 9
    ls[1] = L.canonical_json(e).encode(); write_lines(p, ls)
    assert "entry_hash_mismatch" in reasons(L.verify_log(p, verify_key=auditor)[1])

def test_rehash_without_private_key(p, signer, auditor):
    fill(p, signer); es = [json.loads(l) for l in lines(p)]
    es[1]["parameters"]["x"] = 9; prev = es[0]["entry_hash"]
    for e in es[1:]:
        e["prev_log_hash"] = prev; e["entry_hash"] = L.compute_entry_hash(e); prev = e["entry_hash"]
    write_lines(p, [L.canonical_json(e).encode() for e in es])
    issues = L.verify_log(p, verify_key=auditor)[1]
    assert {i["line"] for i in issues if i["reason"] == "signature_invalid"} == {1, 2}

def test_other_key_same_alg(p, alg, auditor):
    fill(p, G.generate(alg))
    assert "unknown_key_id" in reasons(L.verify_log(p, verify_key=auditor)[1])

def test_spoofed_key_id(p, alg, signer, auditor):
    fill(p, G.generate(alg)); es = [json.loads(l) for l in lines(p)]
    for e in es: e["key_id"] = signer.key_id
    write_lines(p, [L.canonical_json(e).encode() for e in es])
    assert "signature_invalid" in reasons(L.verify_log(p, verify_key=auditor)[1])

def test_bit_flip_in_signature(p, signer, auditor):
    fill(p, signer); es = [json.loads(l) for l in lines(p)]
    s = es[0]["signature"]; es[0]["signature"] = s[:-1] + ("0" if s[-1] != "0" else "1")
    write_lines(p, [L.canonical_json(e).encode() for e in es])
    assert "signature_invalid" in reasons(L.verify_log(p, verify_key=auditor)[1])

def test_wrong_length_signature_is_schema_violation(p, signer):
    fill(p, signer, 1); e = json.loads(lines(p)[0]); e["signature"] = e["signature"][:-2]
    write_lines(p, [L.canonical_json(e).encode()])
    issues = L.verify_log(p)[1]
    assert any("signature for" in x for i in issues for x in i.get("errors", []))

def test_unknown_alg_key_id_rejected(p, signer):
    fill(p, signer, 1); e = json.loads(lines(p)[0]); e["key_id"] = "rsa-4096:" + "0" * 16
    write_lines(p, [L.canonical_json(e).encode()])
    assert "schema_violation" in reasons(L.verify_log(p)[1])

def test_domain_separation_context():
    """ML-DSA signatures are bound to CONTEXT: a signature made with no/other context fails."""
    s = G.MLDSASigner.generate(65); h = "ab" * 32
    raw_noctx = s._priv.sign(h.encode()).hex()
    raw_other = s._priv.sign(h.encode(), b"other-app").hex()
    assert s.verifier.verify(h, s.sign(h))
    assert not s.verifier.verify(h, raw_noctx) and not s.verifier.verify(h, raw_other)

# --- hybrid specifics: both halves must hold ---
def _hybrid_log(p):
    s = G.HybridSigner.generate(); fill(p, s, 2); return s

def test_hybrid_forged_classical_half_fails(p):
    s = _hybrid_log(p); es = [json.loads(l) for l in lines(p)]
    evil = G.Ed25519Signer.generate()   # e.g. Ed25519 broken by a quantum computer
    es[0]["signature"] = evil.sign(es[0]["entry_hash"]) + es[0]["signature"][128:]
    write_lines(p, [L.canonical_json(e).encode() for e in es])
    assert "signature_invalid" in reasons(L.verify_log(p, verify_key=s.verifier)[1])

def test_hybrid_forged_pq_half_fails(p):
    s = _hybrid_log(p); es = [json.loads(l) for l in lines(p)]
    evil = G.MLDSASigner.generate(65)
    es[0]["signature"] = es[0]["signature"][:128] + evil.sign(es[0]["entry_hash"])
    write_lines(p, [L.canonical_json(e).encode() for e in es])
    assert "signature_invalid" in reasons(L.verify_log(p, verify_key=s.verifier)[1])

def test_hybrid_not_downgradable_to_ed25519(p):
    """Auditor holding only the Ed25519 half must not accept a hybrid log as Ed25519-signed."""
    s = _hybrid_log(p)
    assert "unknown_key_id" in reasons(L.verify_log(p, verify_key=s.ed.verifier)[1])

def test_hybrid_rejects_wrong_key_pairing():
    with pytest.raises(ValueError):
        G.HybridVerifier(G.MLDSASigner.generate(65).verifier, G.MLDSASigner.generate(65).verifier)

# --- cross-algorithm isolation & compatibility ---
def test_ed25519_logs_from_0_2_still_verify(p):
    s = G.Ed25519Signer.generate(); fill(p, s)
    assert L.verify_log(p, verify_key=G.load_verifier_pem(s.public_pem()))[0]

def test_mldsa_auditor_rejects_ed25519_log(p):
    fill(p, G.Ed25519Signer.generate())
    assert not L.verify_log(p, verify_key=G.MLDSASigner.generate(65).verifier)[0]

def test_backcompat_ed25519_classes():
    s = G.Ed25519Signer.generate()
    assert isinstance(G.Ed25519Verifier.from_pem(s.public_pem()), G.Verifier)
    with pytest.raises(ValueError): G.Ed25519Verifier.from_pem(G.MLDSASigner.generate(44).public_pem())

def test_migrate_legacy_to_pq(tmp_path, alg):
    src, dst = str(tmp_path / "old"), str(tmp_path / "new")
    o = OLD.AppendOnlyLog(src)
    for i in range(3): o.append("action", "a", 0, "m", {"v": i}, None)
    s = G.generate(alg)
    rep = L.migrate_legacy_log(src, dst, signer=s, expected_legacy_head=o.last_hash())
    assert rep["signing_key_id"] == s.key_id
    assert L.verify_log(dst, verify_key=s.verifier, expected_head=tuple(rep["new_head"]))[0]

def test_generate_unknown_alg():
    with pytest.raises(ValueError): G.generate("ml-dsa-99")

# --- CLI ---
@pytest.mark.parametrize("cli_alg", ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "hybrid"])
def test_cli_keygen_verify_migrate(tmp_path, capsys, cli_alg):
    pre = str(tmp_path / "w")
    assert main(["keygen", "--signing", pre, "--alg", cli_alg]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["alg"] == (G.HYBRID if cli_alg == "hybrid" else cli_alg)
    assert stat.S_IMODE(os.stat(info["private"]).st_mode) == 0o600
    assert main(["keygen", "--signing", pre, "--alg", cli_alg]) == 2      # no overwrite
    src, dst = str(tmp_path / "old"), str(tmp_path / "new")
    OLD.AppendOnlyLog(src).append("action", "a", 0, "m", {}, None)
    assert main(["migrate", src, dst, "--signing-key", info["private"]]) == 0
    capsys.readouterr()
    assert main(["verify", dst, "--pubkey", info["public"]]) == 0
    other = str(tmp_path / "o"); main(["keygen", "--signing", other, "--alg", cli_alg]); capsys.readouterr()
    assert main(["verify", dst, "--pubkey", other + ".pub"]) == 1

def test_cli_ed25519_shorthand_still_works(tmp_path, capsys):
    assert main(["keygen", "--ed25519", str(tmp_path / "e")]) == 0
    assert json.loads(capsys.readouterr().out)["alg"] == "ed25519"
