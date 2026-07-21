# keys.py
#
# Key material management: per-role secrets and per-dataset wrapped DEKs.
# Kept separate from abac.py (policy CRUD/lookup) and crypto_utils.py (pure
# crypto primitives, no Mongo).
import os
from datetime import datetime, timezone

from pymongo import MongoClient, ReturnDocument

import settings

_client = MongoClient(settings.MONGO_URI)
_role_secrets = _client[settings.MONGO_DB]["role_secrets"]
_dataset_keys = _client[settings.MONGO_DB]["dataset_keys"]


def get_or_create_role_secret(role: str) -> bytes:
    """
    Returns the role's root secret, generating it on first use. The upsert
    is atomic, so concurrent first-encounters of a brand-new role can't race
    into two different secrets.
    """
    doc = _role_secrets.find_one_and_update(
        {"role": role},
        {"$setOnInsert": {"secret": os.urandom(32), "created_at": datetime.now(timezone.utc)}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return bytes(doc["secret"])


def get_role_key(role: str) -> bytes:
    """A role's KEK — the role secret used directly, no tier chain."""
    return get_or_create_role_secret(role)


def store_wrapped_key(dataset_name: str, role: str, wrapped_dek: bytes):
    _dataset_keys.update_one(
        {"dataset_name": dataset_name},
        {"$set": {f"wrapped_keys.{role}": wrapped_dek}},
        upsert=True,
    )


def get_wrapped_key(dataset_name: str, role: str) -> bytes | None:
    doc = _dataset_keys.find_one(
        {"dataset_name": dataset_name},
        {"_id": 0, f"wrapped_keys.{role}": 1},
    )
    if not doc:
        return None
    return doc.get("wrapped_keys", {}).get(role)


def get_any_wrapped_entry(dataset_name: str) -> tuple[str, bytes] | None:
    """
    Returns (role, wrapped_dek) for any one role with a wrapped key on this
    dataset — enough to unwrap the current DEK regardless of which policy is
    in effect right now. Used to decrypt a dataset ahead of re-encrypting it
    against an updated policy.
    """
    doc = _dataset_keys.find_one({"dataset_name": dataset_name})
    if not doc or not doc.get("wrapped_keys"):
        return None
    role, wrapped_dek = next(iter(doc["wrapped_keys"].items()))
    return role, wrapped_dek


def delete_dataset_keys(dataset_name: str):
    """Clears all wrapped-key entries for a dataset, e.g. before re-wrapping against a new policy."""
    _dataset_keys.delete_one({"dataset_name": dataset_name})
