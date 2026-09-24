"""Ed25519 signing for independent auditors.

The writer holds the private key and signs each entry's `entry_hash`; auditors get only the
public key, so they can verify every entry but cannot forge one (unlike HMAC, where the
verification key is also the signing key).

Requires the optional dependency:  pip install "sentinel_dot[ed25519]"
"""
import hashlib
from typing import Union

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
except ImportError as _e:  # pragma: no cover
    raise ImportError('Ed25519 support needs: pip install "sentinel_dot[ed25519]"') from _e


def _key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


class Ed25519Verifier:
    """Public-key side: hand this (or its PEM) to auditors."""

    def __init__(self, public_key: Ed25519PublicKey):
        self._pub = public_key
        self.key_id = _key_id(public_key)

    @classmethod
    def from_pem(cls, data: Union[bytes, str]) -> "Ed25519Verifier":
        if isinstance(data, str):
            data = data.encode()
        k = serialization.load_pem_public_key(data)
        if not isinstance(k, Ed25519PublicKey):
            raise ValueError("not an Ed25519 public key")
        return cls(k)

    @classmethod
    def from_file(cls, path: str) -> "Ed25519Verifier":
        with open(path, "rb") as f:
            return cls.from_pem(f.read())

    def public_pem(self) -> bytes:
        return self._pub.public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)

    def verify(self, entry_hash: str, signature_hex: str) -> bool:
        try:
            self._pub.verify(bytes.fromhex(signature_hex), entry_hash.encode("ascii"))
            return True
        except (InvalidSignature, ValueError):
            return False


class Ed25519Signer:
    """Private-key side: only the log writer holds this."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._priv = private_key
        self.verifier = Ed25519Verifier(private_key.public_key())
        self.key_id = self.verifier.key_id

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, data: Union[bytes, str], password: bytes = None) -> "Ed25519Signer":
        if isinstance(data, str):
            data = data.encode()
        k = serialization.load_pem_private_key(data, password=password)
        if not isinstance(k, Ed25519PrivateKey):
            raise ValueError("not an Ed25519 private key")
        return cls(k)

    @classmethod
    def from_file(cls, path: str, password: bytes = None) -> "Ed25519Signer":
        with open(path, "rb") as f:
            return cls.from_pem(f.read(), password)

    def private_pem(self, password: bytes = None) -> bytes:
        enc = (serialization.BestAvailableEncryption(password) if password
               else serialization.NoEncryption())
        return self._priv.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8, enc)

    def public_pem(self) -> bytes:
        return self.verifier.public_pem()

    def sign(self, entry_hash: str) -> str:
        return self._priv.sign(entry_hash.encode("ascii")).hex()
