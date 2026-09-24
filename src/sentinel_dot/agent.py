"""High-level helpers for recording AI agent actions."""
import base64, functools, os
from typing import Any, Callable, Dict, Optional
from .log import AppendOnlyLog, LogError


def load_key(env: str = "SENTINEL_DOT_KEY") -> bytes:
    """Load a base64 HMAC key (>=32 bytes) from an environment variable."""
    raw = os.environ.get(env)
    if not raw:
        raise LogError(f"{env} not set")
    k = base64.b64decode(raw)
    if len(k) < 32:
        raise LogError(f"{env} must decode to at least 32 bytes")
    return k


def _jsonable(v: Any) -> Any:
    """Coerce values into the strict schema: floats -> repr strings, others -> str."""
    if isinstance(v, bool) or v is None or isinstance(v, (int, str)):
        return v
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    return repr(v)


class AgentRecorder:
    """Records an agent's tool calls, outcomes and refusals into a signed hash chain.

    >>> rec = AgentRecorder("agent.jsonl", agent_id="planner", key=load_key())
    >>> @rec.tool
    ... def search(query: str): ...
    """

    def __init__(self, path: str, agent_id: str, key: Optional[bytes] = None,
                 round_: int = 0, max_result_chars: int = 2000, signer=None):
        self.log = AppendOnlyLog(path, key=key, signer=signer)
        self.agent_id = agent_id
        self.round = round_
        self.max_result_chars = max_result_chars

    def action(self, action_type: str, parameters: Dict[str, Any],
               permission_token: Optional[str] = None) -> Dict[str, Any]:
        return self.log.append("action", self.agent_id, self.round, action_type,
                               _jsonable(parameters), permission_token)

    def reject(self, action_type: str, reason: str, parameters: Dict[str, Any] = None):
        p = dict(_jsonable(parameters or {}), reason=reason)
        return self.log.append("rejection", self.agent_id, self.round, action_type, p, None)

    def next_round(self, note: str = "") -> Dict[str, Any]:
        """Close the round. Anchor the returned head externally."""
        e = self.log.append("round_boundary", self.agent_id, self.round, "round_end",
                            {"note": note}, None)
        self.round += 1
        return e

    def head(self):
        return self.log.head()

    def tool(self, fn: Callable = None, *, name: str = None, token: Callable[..., Optional[str]] = None):
        """Decorator: log each call (args) and its outcome (result or error)."""
        def wrap(f):
            tname = name or f.__name__

            @functools.wraps(f)
            def inner(*args, **kwargs):
                tok = token(*args, **kwargs) if token else None
                call = self.action(f"tool:{tname}", {"args": list(args), "kwargs": kwargs}, tok)
                try:
                    result = f(*args, **kwargs)
                except Exception as ex:
                    self.action(f"tool_error:{tname}", {"call_seq": call["seq"],
                                "error": f"{type(ex).__name__}: {ex}"[:self.max_result_chars]})
                    raise
                self.action(f"tool_result:{tname}", {"call_seq": call["seq"],
                            "result": repr(result)[:self.max_result_chars]})
                return result
            return inner
        return wrap(fn) if fn else wrap
