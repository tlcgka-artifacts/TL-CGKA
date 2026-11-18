"""Ristretto255 group operations, X25519 key exchange and AES-128-GCM."""
import ctypes
import ctypes.util
import hashlib
import hmac
import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .codec import ProtocolError, pack, require

ORDER = 2**252 + 27742317777372353535851937790883648493
IDENTITY = bytes(32)
_name = os.environ.get("TLCGKA_LIBSODIUM") or ctypes.util.find_library("sodium")
if not _name:
    raise RuntimeError("libsodium with Ristretto255 support is required")
_lib = ctypes.CDLL(_name)
_lib.sodium_init.restype = ctypes.c_int
if _lib.sodium_init() < 0:
    raise RuntimeError("sodium_init failed")
for _fn, _arity in [
    ("crypto_core_ristretto255_add", 3), ("crypto_core_ristretto255_sub", 3),
    ("crypto_core_ristretto255_from_hash", 2),
    ("crypto_scalarmult_ristretto255", 3), ("crypto_scalarmult_ristretto255_base", 2),
    ("crypto_core_ristretto255_is_valid_point", 1),
]:
    _f = getattr(_lib, _fn)
    _f.argtypes = [ctypes.c_void_p] * _arity
    _f.restype = ctypes.c_int


def digest(label, *parts):
    return hashlib.sha256(pack(("TL-CGKA/v1", label, parts))).digest()


def scalar_bytes(s):
    return (s % ORDER).to_bytes(32, "little")


def scalar_read(data):
    require(isinstance(data, bytes) and len(data) == 32, "bad scalar encoding")
    s = int.from_bytes(data, "little")
    require(s < ORDER, "noncanonical scalar")
    return s


def scalar():
    # Rejection sampling, not modulo reduction of 32 random bytes.
    while True:
        value = int.from_bytes(os.urandom(32), "little") & ((1 << 253) - 1)
        if 0 < value < ORDER:
            return value


def hscalar(label, *parts):
    counter = 0
    while True:
        s = int.from_bytes(hashlib.sha512(pack(("TL-CGKA/v1", label, parts, counter))).digest(), "little") % ORDER
        if s:
            return s
        counter += 1


def valid(point, nonzero=False):
    return (isinstance(point, bytes) and len(point) == 32
            and bool(_lib.crypto_core_ristretto255_is_valid_point(point))
            and (not nonzero or point != IDENTITY))


def point(point, nonzero=False):
    require(valid(point, nonzero), "invalid Ristretto255 point")
    return point


def _call(fn, *args):
    out = ctypes.create_string_buffer(32)
    if getattr(_lib, fn)(out, *args) != 0:
        raise ProtocolError(f"libsodium operation failed: {fn}")
    return out.raw


def add(a, b):
    return _call("crypto_core_ristretto255_add", point(a), point(b))


def sub(a, b):
    return _call("crypto_core_ristretto255_sub", point(a), point(b))


def mul(s, p):
    point(p)
    if s % ORDER == 0 or p == IDENTITY:
        return IDENTITY
    return _call("crypto_scalarmult_ristretto255", scalar_bytes(s), p)


def base(s):
    return IDENTITY if s % ORDER == 0 else _call("crypto_scalarmult_ristretto255_base", scalar_bytes(s))


def hgroup(label, *parts):
    return _call("crypto_core_ristretto255_from_hash",
                 hashlib.sha512(pack(("TL-CGKA/v1", label, parts))).digest())


def total(points):
    acc = IDENTITY
    for p in points:
        acc = add(acc, p)
    return acc


def kdf(label, *parts):
    """HKDF-SHA256 extract/expand with explicit domain and context."""
    prk = hmac.new(bytes(32), pack(parts), hashlib.sha256).digest()
    return hmac.new(prk, pack(("TL-CGKA/v1", label)) + b"\x01", hashlib.sha256).digest()


def seal(key, plaintext, ad):
    nonce = os.urandom(12)
    return nonce + AESGCM(key[:16]).encrypt(nonce, plaintext, pack(ad))


def open_seal(key, ciphertext, ad):
    require(isinstance(ciphertext, bytes) and len(ciphertext) >= 28, "truncated AEAD")
    try:
        return AESGCM(key[:16]).decrypt(ciphertext[:12], ciphertext[12:], pack(ad))
    except InvalidTag as exc:
        raise ProtocolError("AEAD authentication failed") from exc


def sign(sk, message):
    r = scalar()
    R, pk = base(r), base(sk)
    c = hscalar("signature", R, pk, message)
    return (R, scalar_bytes(r + c * sk))


def verify(pk, message, signature):
    try:
        R, z = signature
        point(R, True)
        return base(scalar_read(z)) == add(R, mul(hscalar("signature", R, pk, message), pk))
    except (ValueError, TypeError):
        return False


def nike_gen():
    sk = x25519.X25519PrivateKey.generate()
    return sk.private_bytes_raw(), sk.public_key().public_bytes_raw()


def nike_public(sk):
    return x25519.X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw()


def nike(sk, pk):
    try:
        return x25519.X25519PrivateKey.from_private_bytes(sk).exchange(
            x25519.X25519PublicKey.from_public_bytes(pk))
    except ValueError as exc:
        raise ProtocolError("invalid X25519 key/shared secret") from exc
