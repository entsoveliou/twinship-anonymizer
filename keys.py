# keys.py
#
# Key material management: per-organization secrets and per-dataset wrapped
# DEKs. Kept separate from abac.py (policy CRUD/lookup) and crypto_utils.py
# (pure crypto primitives, no Mongo).
import os
from datetime import datetime, timezone

from pymongo import MongoClient, ReturnDocument

import settings
from crypto_utils import derive_tier_key

_client = MongoClient(settings.MONGO_URI)
_org_secrets = _client[settings.MONGO_DB]["org_secrets"]
_dataset_keys = _client[settings.MONGO_DB]["dataset_keys"]


def get_or_create_org_secret(organization_id: str) -> bytes:
    """
    Returns the organization's root secret, generating it on first use.
    The upsert is atomic, so concurrent first-encounters of a brand-new org
    can't race into two different secrets.
    """
    doc = _org_secrets.find_one_and_update(
        {"organizationId": organization_id},
        {"$setOnInsert": {"secret": os.urandom(32), "created_at": datetime.now(timezone.utc)}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return bytes(doc["secret"])


def get_org_tier_key(organization_id: str, access: str) -> bytes:
    """Convenience: org secret + tier derivation in one call."""
    secret = get_or_create_org_secret(organization_id)
    return derive_tier_key(secret, access)


def store_wrapped_key(dataset_name: str, organization_id: str, access: str, wrapped_dek: bytes):
    _dataset_keys.update_one(
        {"dataset_name": dataset_name},
        {"$set": {f"wrapped_keys.{organization_id}": {"access": access, "wrapped_dek": wrapped_dek}}},
        upsert=True,
    )


def get_wrapped_key(dataset_name: str, organization_id: str) -> dict | None:
    doc = _dataset_keys.find_one(
        {"dataset_name": dataset_name},
        {"_id": 0, f"wrapped_keys.{organization_id}": 1},
    )
    if not doc:
        return None
    return doc.get("wrapped_keys", {}).get(organization_id)


def get_any_wrapped_entry(dataset_name: str) -> tuple[str, str, bytes] | None:
    """
    Returns (organizationId, access, wrapped_dek) for any one org with a
    wrapped key on this dataset — enough to unwrap the current DEK
    regardless of which policy is in effect right now. Used to decrypt a
    dataset ahead of re-encrypting it against an updated policy.
    """
    doc = _dataset_keys.find_one({"dataset_name": dataset_name})
    if not doc or not doc.get("wrapped_keys"):
        return None
    org_id, entry = next(iter(doc["wrapped_keys"].items()))
    return org_id, entry["access"], entry["wrapped_dek"]


def delete_dataset_keys(dataset_name: str):
    """Clears all wrapped-key entries for a dataset, e.g. before re-wrapping against a new policy."""
    _dataset_keys.delete_one({"dataset_name": dataset_name})
