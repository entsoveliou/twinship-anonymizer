# crypto_utils.py
#
# Envelope encryption primitives. No Mongo/network access here — pure crypto,
# so it stays easy to reason about and test in isolation.
#
# Content is encrypted once per file with a random Data Encryption Key (DEK).
# The DEK itself is then "wrapped" (encrypted) separately per organization
# with a Key Encryption Key (KEK) derived from that org's secret. See keys.py
# for where org secrets and wrapped DEKs are stored/looked up.
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac

DEK_SIZE = 32   # 256-bit content key
NONCE_SIZE = 12  # AES-GCM standard nonce size

# Access tiers ordered highest -> lowest. Used to build a one-way hash chain
# per organization: a key derived at a higher tier can re-derive every lower
# tier's key, but never the reverse.
TIER_ORDER = ["admin", "rw", "ro", "c-ro"]


def generate_dek() -> bytes:
    return os.urandom(DEK_SIZE)


def encrypt_content(data_bytes: bytes, dek: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(dek)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data_bytes, aad)
    return nonce + ciphertext


def decrypt_content(encrypted_data: bytes, dek: bytes, aad: bytes) -> bytes | None:
    try:
        aesgcm = AESGCM(dek)
        nonce = encrypted_data[:NONCE_SIZE]
        ciphertext = encrypted_data[NONCE_SIZE:]
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception:
        return None


def wrap_key(kek: bytes, dek: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(kek)
    nonce = os.urandom(NONCE_SIZE)
    wrapped = aesgcm.encrypt(nonce, dek, aad)
    return nonce + wrapped


def unwrap_key(kek: bytes, wrapped_dek: bytes, aad: bytes) -> bytes | None:
    try:
        aesgcm = AESGCM(kek)
        nonce = wrapped_dek[:NONCE_SIZE]
        ciphertext = wrapped_dek[NONCE_SIZE:]
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception:
        return None


def derive_tier_key(org_secret: bytes, tier: str) -> bytes:
    """
    Derives an organization's KEK for a given access tier via a one-way
    HMAC-SHA256 chain over TIER_ORDER (admin -> rw -> ro -> c-ro). Holding the
    'admin' key lets you recompute every key below it; holding e.g. 'ro'
    cannot get you back to 'admin' or 'rw'.
    """
    if tier not in TIER_ORDER:
        raise ValueError(f"Unknown access tier: {tier}")

    key = org_secret
    for t in TIER_ORDER:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(t.encode())
        key = h.finalize()
        if t == tier:
            return key
