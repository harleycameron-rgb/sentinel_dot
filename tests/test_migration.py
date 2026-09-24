"""Legacy-log migration tests. Fixtures are written by the ORIGINAL log.py
(legacy/legacy_log.py, unmodified) so these test real legacy bytes."""
import json, os, pytest
from sentinel_dot import log as L
from legacy import legacy_log as OLD

KEY = b"migration-key"

@pytest.fixture
def src(tmp_path): return str(tmp_path / "legacy.jsonl")
@pytest.fixture
def dst(tmp_path): return str(tmp_path / "migrated.jsonl")

def legacy_fill(path, params_list):
    lg = OLD.AppendOnlyLog(path)
    for i, p in enumerate(params_list):
        lg.append("action" if i % 3 else "round_boundary", "agent", i // 3, "move", p, None)
    return lg.last_hash()

def lines(p): return open(p, "rb").read().splitlines()
def write_lines(p, ls): open(p, "wb").write(b"".join(l + b"\n" for l in ls))

# --- compatibility: new code reading untouched legacy logs ---
def test_legacy_log_verifies_unkeyed_in_new_code(src):
    head = legacy_fill(src, [{"x": i} for i in range(5)])
    ok, issues = L.verify_log(src, expected_head=(5, head))
    assert ok, issues

def test_new_code_can_append_to_legacy_log(src):
    legacy_fill(src, [{"x": 1}, {"x": 2}])
    lg = L.AppendOnlyLog(src)
    e = lg.append("action", "a", 1, "m", {}, None)
    assert e["seq"] == 2
    assert L.verify_log(src, expected_head=lg.head())[0]
    assert OLD.verify_log(src)[0]  # old verifier still accepts the extended file

def test_legacy_floats_flagged_by_strict_verifier(src):
    legacy_fill(src, [{"v": 1.5}])
    ok, issues = L.verify_log(src)
    assert not ok and issues[0]["reason"] == "schema_violation"

# --- happy-path migration ---
def test_migrate_to_keyed(src, dst):
    head = legacy_fill(src, [{"x": i} for i in range(6)])
    before = open(src, "rb").read()
    rep = L.migrate_legacy_log(src, dst, key=KEY, expected_legacy_head=head)
    assert rep["entries"] == 6 and rep["legacy_head"] == head and rep["keyed"]
    ok, issues = L.verify_log(dst, key=KEY, expected_head=tuple(rep["new_head"]))
    assert ok, issues
    assert open(src, "rb").read() == before          # source untouched
    assert not L.verify_log(dst)[0]                    # unkeyed check fails on keyed log

def test_migration_preserves_content(src, dst):
    legacy_fill(src, [{"x": i, "tag": f"t{i}"} for i in range(4)])
    L.migrate_legacy_log(src, dst, key=KEY)
    for a, b in zip(map(json.loads, lines(src)), map(json.loads, lines(dst))):
        for k in ("seq", "msg_type", "sender", "round", "action_type",
                  "parameters", "permission_token"):
            assert a[k] == b[k]

def test_migrated_log_accepts_new_appends(src, dst):
    legacy_fill(src, [{"x": 1}])
    L.migrate_legacy_log(src, dst, key=KEY)
    lg = L.AppendOnlyLog(dst, key=KEY)
    assert lg.append("action", "a", 0, "m", {}, None)["seq"] == 1
    assert L.verify_log(dst, key=KEY, expected_head=lg.head())[0]

def test_unkeyed_migration_is_deterministic(src, tmp_path):
    legacy_fill(src, [{"x": i} for i in range(3)])
    a, b = str(tmp_path / "a"), str(tmp_path / "b")
    L.migrate_legacy_log(src, a); L.migrate_legacy_log(src, b)
    assert open(a, "rb").read() == open(b, "rb").read()

def test_empty_legacy_log(src, dst):
    open(src, "w").close()
    rep = L.migrate_legacy_log(src, dst, key=KEY)
    assert rep["entries"] == 0 and rep["new_head"] == (0, L.GENESIS_HASH)
    assert os.path.getsize(dst) == 0

# --- float conversion ---
def test_floats_converted_exactly(src, dst):
    legacy_fill(src, [{"dt": 0.1, "nested": [{"g": 2.5e-10}], "n": 3}])
    rep = L.migrate_legacy_log(src, dst, key=KEY)
    p = json.loads(lines(dst)[0])["parameters"]
    assert p == {"dt": "0.1", "nested": [{"g": "2.5e-10"}], "n": 3}
    assert float(p["dt"]) == 0.1
    assert set(rep["converted_floats"]) == {"line0.parameters.dt",
                                            "line0.parameters.nested[0].g"}

def test_nan_and_inf_converted(src, dst):
    legacy_fill(src, [{"a": float("nan"), "b": float("inf"), "c": float("-inf")}])
    assert b"NaN" in lines(src)[0]                     # legacy wrote invalid JSON
    L.migrate_legacy_log(src, dst, key=KEY)
    assert json.loads(lines(dst)[0])["parameters"] == {"a": "NaN", "b": "Infinity", "c": "-Infinity"}
    assert L.verify_log(dst, key=KEY)[0]

def test_convert_floats_disabled_aborts(src, dst):
    legacy_fill(src, [{"v": 1.5}])
    with pytest.raises(L.LogError, match="strict schema"):
        L.migrate_legacy_log(src, dst, key=KEY, convert_floats=False)
    assert not os.path.exists(dst)

# --- refusal: never re-sign tampered or incomplete data ---
def tamper(src, i, fn):
    ls = lines(src); e = json.loads(ls[i]); fn(e); ls[i] = OLD.canonical_json(e).encode()
    write_lines(src, ls)

def test_refuses_tampered_entry(src, dst):
    legacy_fill(src, [{"x": i} for i in range(3)])
    tamper(src, 1, lambda e: e["parameters"].update(x=99))
    with pytest.raises(L.LogError, match="entry hash mismatch"):
        L.migrate_legacy_log(src, dst, key=KEY)
    assert not os.path.exists(dst)

def test_refuses_deleted_middle_entry(src, dst):
    legacy_fill(src, [{"x": i} for i in range(3)])
    ls = lines(src); del ls[1]; write_lines(src, ls)
    with pytest.raises(L.LogError):
        L.migrate_legacy_log(src, dst, key=KEY)

def test_refuses_truncation_with_anchor(src, dst):
    head = legacy_fill(src, [{"x": i} for i in range(4)])
    write_lines(src, lines(src)[:2])
    with pytest.raises(L.LogError, match="legacy head mismatch"):
        L.migrate_legacy_log(src, dst, key=KEY, expected_legacy_head=head)

def test_refuses_torn_tail(src, dst):
    legacy_fill(src, [{"x": 1}]); open(src, "ab").write(b'{"seq":1,"msg')
    with pytest.raises(L.TornWriteError):
        L.migrate_legacy_log(src, dst, key=KEY)

def test_refuses_invalid_json_line(src, dst):
    legacy_fill(src, [{"x": 1}]); open(src, "ab").write(b"garbage\n")
    with pytest.raises(L.LogError, match="invalid JSON"):
        L.migrate_legacy_log(src, dst, key=KEY)

def test_refuses_legacy_extra_fields(src, dst):
    legacy_fill(src, [{"x": 1}])
    def add(e): e["note"] = "x"; e["entry_hash"] = OLD.compute_entry_hash(e)
    tamper(src, 0, add)
    assert OLD.verify_log(src)[0]                      # legacy accepted it
    with pytest.raises(L.LogError, match="unknown fields"):
        L.migrate_legacy_log(src, dst, key=KEY)

def test_refuses_legacy_values_invalid_under_strict_schema(src, dst):
    lg = OLD.AppendOnlyLog(src); lg.append("action", "a", -1, "m", {}, None)
    with pytest.raises(L.LogError, match="strict schema"):
        L.migrate_legacy_log(src, dst, key=KEY)

def test_refuses_in_place_migration(src):
    legacy_fill(src, [{"x": 1}])
    with pytest.raises(L.LogError, match="dst must differ"):
        L.migrate_legacy_log(src, src, key=KEY)

def test_failed_migration_leaves_existing_dst_intact(src, dst):
    open(dst, "wb").write(b"previous\n")
    legacy_fill(src, [{"x": 1}]); tamper(src, 0, lambda e: e.update(sender="evil"))
    with pytest.raises(L.LogError):
        L.migrate_legacy_log(src, dst, key=KEY)
    assert open(dst, "rb").read() == b"previous\n"

def test_large_legacy_log(src, dst):
    head = legacy_fill(src, [{"i": i, "f": i / 7} for i in range(500)])
    rep = L.migrate_legacy_log(src, dst, key=KEY, expected_legacy_head=head)
    assert rep["entries"] == 500 and len(rep["converted_floats"]) == 500  # 0/7 == 0.0 is still a float
    assert L.verify_log(dst, key=KEY, expected_head=tuple(rep["new_head"]))[0]
