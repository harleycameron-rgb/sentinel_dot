"""Public-key signing for independent auditors: Ed25519, ML-DSA (FIPS 204) and hybrid.

The writer holds the private key and signs each entry's `entry_hash`. Auditors get only the
public key, so they can verify every entry but cannot forge one (unlike HMAC, where the
verification key is also the signing key).

Algorithms (`alg`, also the key_id prefix):
  ed25519                    classical, 64-byte signatures, NOT quantum-resistant
  ml-dsa-44 | 65 | 87        post-quantum (FIPS 204), NIST categories 2 / 3 / 5,
                             signatures 2420 / 3309 / 4627 bytes
  hybrid-ed25519-ml-dsa-65   both at once; forging needs breaking BOTH (recommended during
                             the post-quantum transition)

ML-DSA signs with FIPS 204 context string CONTEXT for domain separation. Ed25519 signs the
bare entry_hash, unchanged from sentinel_dot 0.2, so existing signed logs keep verifying.

Requires:  pip install "sentinel_dot[ed25519]"  (cryptography >= 48 for ML-DSA)
"""
import hashlib
import re
from typing import List, Optional, Union

try:
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization as S
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
except ImportError as _e:  # pragma: no cover
    raise ImportError('signing needs: pip install "sentinel_dot[ed25519]"') from _e

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa
    _ML = {"ml-dsa-44": (_mldsa.MLDSA44PrivateKey, _mldsa.MLDSA44PublicKey),
           "ml-dsa-65": (_mldsa.MLDSA65PrivateKey, _mldsa.MLDSA65PublicKey),
           "ml-dsa-87": (_mldsa.MLDSA87PrivateKey, _mldsa.MLDSA87PublicKey)}
except ImportError:  # cryptography < 48
    _mldsa, _ML = None, {}

CONTEXT = b"sentinel_dot/entry/v1"
HYBRID = "hybrid-ed25519-ml-dsa-65"
SIG_BYTES = {"ed25519": 64, "ml-dsa-44": 2420, "ml-dsa-65": 3309, "ml-dsa-87": 4627,
             HYBRID: 64 + 3309}
ALGORITHMS = list(SIG_BYTES)
KEY_ID_RE = re.compile(r"^(" + "|".join(map(re.escape, ALGORITHMS)) + r"):[0-9a-f]{16}$")

__all__ = ["Signer", "Verifier", "Ed25519Signer", "Ed25519Verifier", "MLDSASigner",
           "MLDSAVerifier", "HybridSigner", "HybridVerifier", "load_signer", "load_verifier",
           "generate", "ALGORITHMS", "SIG_BYTES", "CONTEXT", "mldsa_available"]


def mldsa_available() -> bool:
    if not _ML:
        return False
    try:
        _ML["ml-dsa-65"][0].generate()
        return True
    except UnsupportedAlgorithm:
        return False


def _need_mldsa():
    if not mldsa_available():
        raise ImportError("ML-DSA needs cryptography >= 48 built with OpenSSL/AWS-LC ML-DSA "
                          'support: pip install -U "cryptography>=48"')


def _raw_pub(pub) -> bytes:
    return pub.public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)


def _kid(alg: str, raw: bytes) -> str:
    return f"{alg}:{hashlib.sha256(raw).hexdigest()[:16]}"


def _pem_blocks(data: Union[bytes, str]) -> List[bytes]:
    if isinstance(data, str):
        data = data.encode()
    blocks = re.findall(rb"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----\s*", data, re.S)
    if not blocks:
        raise ValueError("no PEM block found")
    return blocks


def _pub_alg(pub) -> str:
    if isinstance(pub, Ed25519PublicKey):
        return "ed25519"
    for alg, (_, P) in _ML.items():
        if isinstance(pub, P):
            return alg
    raise ValueError(f"unsupported public key type {type(pub).__name__}")


# ---------------------------------------------------------------------------
# single-algorithm keys
# ---------------------------------------------------------------------------

class Verifier:
    """Public-key side for one algorithm. Hand this (or its PEM) to auditors."""

    def __init__(self, public_key):
        self._pub = public_key
        self.alg = _pub_alg(public_key)
        self.key_id = _kid(self.alg, _raw_pub(public_key))

    @classmethod
    def from_pem(cls, data: Union[bytes, str]) -> "Verifier":
        return load_verifier_pem(data)

    @classmethod
    def from_file(cls, path: str) -> "Verifier":
        with open(path, "rb") as f:
            return load_verifier_pem(f.read())

    def public_pem(self) -> bytes:
        return self._pub.public_bytes(S.Encoding.PEM, S.PublicFormat.SubjectPublicKeyInfo)

    def _verify_raw(self, msg: bytes, sig: bytes) -> bool:
        try:
            if self.alg == "ed25519":
                self._pub.verify(sig, msg)
            else:
                self._pub.verify(sig, msg, CONTEXT)
            return True
        except (InvalidSignature, ValueError):
            return False

    def verify(self, entry_hash: str, signature_hex: str) -> bool:
        try:
            sig = bytes.fromhex(signature_hex)
        except ValueError:
            return False
        if len(sig) != SIG_BYTES[self.alg]:
            return False
        return self._verify_raw(entry_hash.encode("ascii"), sig)


class Signer:
    """Private-key side for one algorithm. Only the log writer holds this."""

    def __init__(self, private_key):
        self._priv = private_key
        self.verifier = Verifier(private_key.public_key())
        self.alg = self.verifier.alg
        self.key_id = self.verifier.key_id

    @classmethod
    def generate(cls, alg: str = "ed25519") -> "Signer":
        return generate(alg)

    @classmethod
    def from_pem(cls, data: Union[bytes, str], password: Optional[bytes] = None) -> "Signer":
        return load_signer_pem(data, password)

    @classmethod
    def from_file(cls, path: str, password: Optional[bytes] = None) -> "Signer":
        with open(path, "rb") as f:
            return load_signer_pem(f.read(), password)

    def private_pem(self, password: Optional[bytes] = None) -> bytes:
        enc = S.BestAvailableEncryption(password) if password else S.NoEncryption()
        return self._priv.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, enc)

    def public_pem(self) -> bytes:
        return self.verifier.public_pem()

    def _sign_raw(self, msg: bytes) -> bytes:
        if self.alg == "ed25519":
            return self._priv.sign(msg)
        return self._priv.sign(msg, CONTEXT)

    def sign(self, entry_hash: str) -> str:
        return self._sign_raw(entry_hash.encode("ascii")).hex()


class Ed25519Verifier(Verifier):
    def __init__(self, public_key):
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("not an Ed25519 public key")
        super().__init__(public_key)

    @classmethod
    def from_pem(cls, data):
        v = load_verifier_pem(data)
        if v.alg != "ed25519":
            raise ValueError("not an Ed25519 public key")
        return v


class Ed25519Signer(Signer):
    def __init__(self, private_key):
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("not an Ed25519 private key")
        super().__init__(private_key)

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, data, password=None):
        s = load_signer_pem(data, password)
        if s.alg != "ed25519":
            raise ValueError("not an Ed25519 private key")
        return s


class MLDSAVerifier(Verifier):
    pass


class MLDSASigner(Signer):
    @classmethod
    def generate(cls, level: int = 65) -> "MLDSASigner":
        _need_mldsa()
        alg = f"ml-dsa-{level}"
        if alg not in _ML:
            raise ValueError("ML-DSA level must be 44, 65 or 87")
        return cls(_ML[alg][0].generate())


# ---------------------------------------------------------------------------
# hybrid: Ed25519 + ML-DSA-65, both must verify
# ---------------------------------------------------------------------------

class HybridVerifier:
    alg = HYBRID

    def __init__(self, ed: Verifier, pq: Verifier):
        if ed.alg != "ed25519" or pq.alg != "ml-dsa-65":
            raise ValueError("hybrid needs an Ed25519 key and an ML-DSA-65 key")
        self.ed, self.pq = ed, pq
        self.key_id = _kid(HYBRID, _raw_pub(ed._pub) + _raw_pub(pq._pub))

    @classmethod
    def from_file(cls, path: str) -> "HybridVerifier":
        with open(path, "rb") as f:
            return load_verifier_pem(f.read())

    def public_pem(self) -> bytes:
        return self.ed.public_pem() + self.pq.public_pem()

    def verify(self, entry_hash: str, signature_hex: str) -> bool:
        try:
            sig = bytes.fromhex(signature_hex)
        except ValueError:
            return False
        if len(sig) != SIG_BYTES[HYBRID]:
            return False
        msg = entry_hash.encode("ascii")
        ok_ed = self.ed._verify_raw(msg, sig[:64])
        ok_pq = self.pq._verify_raw(msg, sig[64:])
        return ok_ed and ok_pq


class HybridSigner:
    alg = HYBRID

    def __init__(self, ed: Signer, pq: Signer):
        self.ed, self.pq = ed, pq
        self.verifier = HybridVerifier(ed.verifier, pq.verifier)
        self.key_id = self.verifier.key_id

    @classmethod
    def generate(cls) -> "HybridSigner":
        _need_mldsa()
        return cls(Ed25519Signer.generate(), MLDSASigner.generate(65))

    @classmethod
    def from_file(cls, path: str, password: Optional[bytes] = None) -> "HybridSigner":
        with open(path, "rb") as f:
            return load_signer_pem(f.read(), password)

    def private_pem(self, password: Optional[bytes] = None) -> bytes:
        return self.ed.private_pem(password) + self.pq.private_pem(password)

    def public_pem(self) -> bytes:
        return self.verifier.public_pem()

    def sign(self, entry_hash: str) -> str:
        msg = entry_hash.encode("ascii")
        return (self.ed._sign_raw(msg) + self.pq._sign_raw(msg)).hex()


# ---------------------------------------------------------------------------
# factories / loaders (auto-detect algorithm from PEM)
# ---------------------------------------------------------------------------

def generate(alg: str = "ed25519"):
    if alg == "ed25519":
        return Ed25519Signer.generate()
    if alg in ("ml-dsa-44", "ml-dsa-65", "ml-dsa-87"):
        return MLDSASigner.generate(int(alg.rsplit("-", 1)[1]))
    if alg == HYBRID or alg == "hybrid":
        return HybridSigner.generate()
    raise ValueError(f"unknown algorithm {alg!r}; choose from {ALGORITHMS}")


def _one_signer(block: bytes, password):
    k = S.load_pem_private_key(block, password=password)
    if isinstance(k, Ed25519PrivateKey):
        return Ed25519Signer(k)
    for alg, (P, _) in _ML.items():
        if isinstance(k, P):
            return MLDSASigner(k)
    raise ValueError(f"unsupported private key type {type(k).__name__}")


def _one_verifier(block: bytes):
    k = S.load_pem_public_key(block)
    if isinstance(k, Ed25519PublicKey):
        return Ed25519Verifier(k)
    return MLDSAVerifier(k)


def load_signer_pem(data, password: Optional[bytes] = None):
    blocks = _pem_blocks(data)
    if len(blocks) == 1:
        return _one_signer(blocks[0], password)
    if len(blocks) == 2:
        a, b = (_one_signer(x, password) for x in blocks)
        ed, pq = (a, b) if a.alg == "ed25519" else (b, a)
        return HybridSigner(ed, pq)
    raise ValueError("expected 1 PEM block (single) or 2 (hybrid)")


def load_verifier_pem(data):
    blocks = _pem_blocks(data)
    if len(blocks) == 1:
        return _one_verifier(blocks[0])
    if len(blocks) == 2:
        a, b = (_one_verifier(x) for x in blocks)
        ed, pq = (a, b) if a.alg == "ed25519" else (b, a)
        return HybridVerifier(ed, pq)
    raise ValueError("expected 1 PEM block (single) or 2 (hybrid)")


def load_signer(path: str, password: Optional[bytes] = None):
    with open(path, "rb") as f:
        return load_signer_pem(f.read(), password)


def load_verifier(path: str):
    with open(path, "rb") as f:
        return load_verifier_pem(f.read())
