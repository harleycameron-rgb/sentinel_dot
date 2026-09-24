import base64, json, secrets, pytest
from sentinel_dot import AgentRecorder, verify_log, load_key, LogError
from sentinel_dot.cli import main

KEY = secrets.token_bytes(32)

def test_tool_decorator_logs_call_and_result(tmp_path):
    p = str(tmp_path / "a.jsonl"); rec = AgentRecorder(p, "planner", key=KEY)
    @rec.tool
    def add(a, b): return a + b
    assert add(2, 3) == 5
    ok, _ = verify_log(p, key=KEY, expected_head=rec.head()); assert ok
    es = rec.log.read_all()
    assert [e["action_type"] for e in es] == ["tool:add", "tool_result:add"]
    assert es[1]["parameters"] == {"call_seq": 0, "result": "5"}

def test_tool_error_logged_and_reraised(tmp_path):
    p = str(tmp_path / "a.jsonl"); rec = AgentRecorder(p, "x", key=KEY)
    @rec.tool(name="boom")
    def f(): raise ValueError("bad")
    with pytest.raises(ValueError): f()
    assert rec.log.read_all()[-1]["action_type"] == "tool_error:boom"

def test_permission_token_and_floats_coerced(tmp_path):
    p = str(tmp_path / "a.jsonl"); rec = AgentRecorder(p, "x", key=KEY)
    @rec.tool(token=lambda amount: "tok-123")
    def pay(amount): return amount
    pay(1.5)
    e = rec.log.read_all()[0]
    assert e["permission_token"] == "tok-123" and e["parameters"]["args"] == ["1.5"]

def test_reject_and_rounds(tmp_path):
    p = str(tmp_path / "a.jsonl"); rec = AgentRecorder(p, "x", key=KEY)
    rec.reject("tool:delete_db", "no permission"); rec.next_round("done"); rec.action("noop", {})
    es = rec.log.read_all()
    assert [e["msg_type"] for e in es] == ["rejection", "round_boundary", "action"]
    assert es[2]["round"] == 1

def test_load_key(monkeypatch):
    monkeypatch.setenv("SENTINEL_DOT_KEY", base64.b64encode(KEY).decode()); assert load_key() == KEY
    monkeypatch.setenv("SENTINEL_DOT_KEY", base64.b64encode(b"short").decode())
    with pytest.raises(LogError): load_key()

def test_cli_roundtrip(tmp_path, monkeypatch, capsys):
    assert main(["keygen"]) == 0
    k = capsys.readouterr().out.strip(); monkeypatch.setenv("K", k)
    p = str(tmp_path / "a.jsonl"); rec = AgentRecorder(p, "x", key=base64.b64decode(k))
    rec.action("a", {}); seq, h = rec.head()
    assert main(["verify", p, "--key-env", "K", "--expect-seq", str(seq), "--expect-hash", h]) == 0
    assert main(["verify", p]) == 1                      # wrong (no) key fails
    assert main(["verify", p, "--key-env", "K", "--expect-seq", "5", "--expect-hash", h]) == 1
    capsys.readouterr(); main(["head", p])
    assert json.loads(capsys.readouterr().out)["next_seq"] == 1
    assert main(["show", p]) == 0
