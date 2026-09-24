import json, os, multiprocessing as mp
import pytest
from sentinel_dot import log as L

KEY = b"test-secret-key"

def reasons(issues): return {i["reason"] for i in issues}

@pytest.fixture
def p(tmp_path): return str(tmp_path / "log.jsonl")

def fill(path, n=4, key=KEY, **kw):
    lg = L.AppendOnlyLog(path, key=key, **kw)
    for i in range(n): lg.append("action", "agent", 0, "move", {"x": i}, None)
    return lg

def lines(p): return open(p, "rb").read().splitlines()
def write_lines(p, ls): open(p, "wb").write(b"".join(l + b"\n" for l in ls))

# --- baseline ---
def test_clean_log_verifies(p):
    lg = fill(p)
    ok, issues = L.verify_log(p, key=KEY, expected_head=lg.head())
    assert ok, issues

def test_empty_and_genesis(p):
    lg = L.AppendOnlyLog(p, key=KEY)
    assert lg.head() == (0, L.GENESIS_HASH)
    e = lg.append("action", "a", 0, "m", {}, None)
    assert e["seq"] == 0 and e["prev_log_hash"] == L.GENESIS_HASH

def test_missing_file(p):
    ok, issues = L.verify_log(p)
    assert not ok and reasons(issues) == {"file_not_found"}

# --- tamper detection ---
def test_single_field_tamper_localized(p):
    fill(p)
    ls = lines(p); e = json.loads(ls[1]); e["parameters"]["x"] = 999
    ls[1] = L.canonical_json(e).encode(); write_lines(p, ls)
    ok, issues = L.verify_log(p, key=KEY)
    assert not ok and [i["line"] for i in issues] == [1]
    assert reasons(issues) == {"entry_hash_mismatch"}

def test_tail_truncation_detected_with_anchor(p):
    head = fill(p).head()
    write_lines(p, lines(p)[:2])
    assert L.verify_log(p, key=KEY)[0]  # indistinguishable without an anchor...
    ok, issues = L.verify_log(p, key=KEY, expected_head=head)
    assert not ok and "head_mismatch" in reasons(issues)  # ...caught with one

def test_full_rewrite_forgery_detected_with_key(p, tmp_path):
    fill(p)
    forged = str(tmp_path / "forged.jsonl")
    fill(forged, key=None)  # attacker lacks the key; re-chains with plain SHA-256
    os.replace(forged, p)
    ok, issues = L.verify_log(p, key=KEY)
    assert not ok and "entry_hash_mismatch" in reasons(issues)

def test_forgery_with_wrong_key_detected(p, tmp_path):
    fill(p); f = str(tmp_path / "f.jsonl"); fill(f, key=b"wrong"); os.replace(f, p)
    assert not L.verify_log(p, key=KEY)[0]

def test_deleted_middle_entry(p):
    fill(p); ls = lines(p); del ls[1]; write_lines(p, ls)
    r = reasons(L.verify_log(p, key=KEY)[1])
    assert {"seq_mismatch", "prev_hash_mismatch"} <= r

def test_reordered_entries(p):
    fill(p); ls = lines(p); ls[1], ls[2] = ls[2], ls[1]; write_lines(p, ls)
    assert "prev_hash_mismatch" in reasons(L.verify_log(p, key=KEY)[1])

def test_tampered_seq_cannot_resync_counter(p):
    fill(p); ls = lines(p); e = json.loads(ls[1]); e["seq"] = 50
    ls[1] = L.canonical_json(e).encode(); write_lines(p, ls)
    issues = L.verify_log(p, key=KEY)[1]
    assert [i["line"] for i in issues if i["reason"] == "seq_mismatch"] == [1]

def test_non_canonical_reencoding_flagged(p):
    fill(p); ls = lines(p)
    ls[0] = json.dumps(json.loads(ls[0]), indent=None).encode()  # spaces after separators
    write_lines(p, ls)
    assert "non_canonical_encoding" in reasons(L.verify_log(p, key=KEY)[1])

# --- schema strictness ---
def test_unknown_field_rejected(p):
    fill(p, 1); e = json.loads(lines(p)[0]); e["extra"] = 1
    e["entry_hash"] = L.compute_entry_hash(e, KEY); write_lines(p, [L.canonical_json(e).encode()])
    issues = L.verify_log(p, key=KEY)[1]
    assert any("unknown field: extra" in x for i in issues for x in i.get("errors", []))

@pytest.mark.parametrize("params", [{"v": float("nan")}, {"v": float("inf")}, {"v": 1.5},
                                    {"v": [1, {"w": 0.1}]}, {"v": {1, 2}}])
def test_bad_parameter_values_refused_on_append(p, params):
    with pytest.raises((L.LogError, ValueError, TypeError)):
        L.AppendOnlyLog(p, key=KEY).append("action", "a", 0, "m", params, None)
    assert not os.path.exists(p) or os.path.getsize(p) == 0

def test_nan_literal_in_file_flagged(p):
    fill(p, 1); ls = lines(p); ls[0] = ls[0].replace(b'"x":0', b'"x":NaN'); write_lines(p, ls)
    assert "invalid_json" in reasons(L.verify_log(p, key=KEY)[1])

@pytest.mark.parametrize("kw,val", [("round_", -1), ("msg_type", "bogus"), ("sender", ""),
                                    ("permission_token", 5), ("round_", True)])
def test_invalid_fields_refused(p, kw, val):
    args = dict(msg_type="action", sender="a", round_=0, action_type="m",
                parameters={}, permission_token=None); args[kw] = val
    with pytest.raises(L.LogError):
        L.AppendOnlyLog(p, key=KEY).append(**args)

def test_bad_hash_format(p):
    fill(p, 1); e = json.loads(lines(p)[0]); e["prev_log_hash"] = "ABC"
    write_lines(p, [L.canonical_json(e).encode()])
    issues = L.verify_log(p, key=KEY)[1]
    assert any("prev_log_hash must be 64" in x for i in issues for x in i.get("errors", []))

# --- crash safety ---
def test_torn_tail_refuses_append(p):
    fill(p, 2); open(p, "ab").write(b'{"seq":2,"msg_ty')
    with pytest.raises(L.TornWriteError):
        L.AppendOnlyLog(p, key=KEY).append("action", "a", 0, "m", {}, None)
    assert "torn_final_line" in reasons(L.verify_log(p, key=KEY)[1])

def test_torn_tail_repair(p):
    fill(p, 2); open(p, "ab").write(b'{"seq":2,"msg_ty')
    lg = L.AppendOnlyLog(p, key=KEY, repair_torn_tail=True)
    e = lg.append("action", "a", 0, "m", {}, None)
    assert e["seq"] == 2
    ok, issues = L.verify_log(p, key=KEY, expected_head=lg.head())
    assert ok, issues

def test_long_last_line_read_backwards(p):
    lg = L.AppendOnlyLog(p, key=KEY)
    lg.append("action", "a", 0, "m", {"blob": "x" * 20000}, None)
    lg.append("action", "a", 0, "m", {"blob": "y" * 10000}, None)
    assert L.verify_log(p, key=KEY, expected_head=lg.head())[0]

def _worker(args):
    path, wid = args
    lg = L.AppendOnlyLog(path, key=KEY)
    for i in range(25): lg.append("action", f"w{wid}", 0, "m", {"i": i}, None)

def test_concurrent_writers_no_fork(p):
    with mp.Pool(4) as pool: pool.map(_worker, [(p, w) for w in range(4)])
    lg = L.AppendOnlyLog(p, key=KEY)
    ok, issues = L.verify_log(p, key=KEY, expected_head=lg.head())
    assert ok, issues[:3]
    assert lg.head()[0] == 100

def test_read_all_raises_on_corrupt_line(p):
    fill(p, 2); ls = lines(p); ls[0] = b"garbage"; write_lines(p, ls)
    with pytest.raises(L.LogError):
        L.AppendOnlyLog(p, key=KEY).read_all()

def test_unkeyed_mode_still_works(p):
    lg = fill(p, key=None)
    assert L.verify_log(p, expected_head=lg.head())[0]
