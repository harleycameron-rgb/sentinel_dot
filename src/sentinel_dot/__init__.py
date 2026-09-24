"""sentinel_dot: tamper-evident, append-only action logs for AI agents."""
from .log import (AppendOnlyLog, verify_log, migrate_legacy_log, compute_entry_hash,
                  canonical_json, validate_schema, GENESIS_HASH, LogError, TornWriteError)
from .agent import AgentRecorder, load_key


def __getattr__(name):  # lazy: Ed25519 needs the optional 'cryptography' dependency
    if name in ("Ed25519Signer", "Ed25519Verifier"):
        from . import signing
        return getattr(signing, name)
    raise AttributeError(name)
__all__ = ["AppendOnlyLog", "verify_log", "migrate_legacy_log", "compute_entry_hash",
           "canonical_json", "validate_schema", "GENESIS_HASH", "LogError",
           "TornWriteError", "AgentRecorder", "load_key",
           "Ed25519Signer", "Ed25519Verifier"]
__version__ = "0.2.0"
