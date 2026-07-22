# abac.py
from fastapi import HTTPException, status
from pymongo import MongoClient

import settings

_client = MongoClient(settings.MONGO_URI)
_collection = _client[settings.MONGO_DB]["policies"]
_prefix_collection = _client[settings.MONGO_DB]["prefix_policies"]


def _find_prefix_policy(dataset_name: str) -> dict | None:
    """
    Fallback tier below the exact per-dataset policy: returns the first
    predefined prefix policy whose prefix the dataset_name starts with, or
    None if none match. Prefix policies are seeded once via
    mongo/init/01-init.js and have no CRUD surface anywhere in the API —
    this is the only place they're read from. Prefix list is expected to
    stay small, so a plain Python scan is fine.
    """
    for doc in _prefix_collection.find({}, {"_id": 0}):
        if dataset_name.startswith(doc["prefix"]):
            return doc
    return None


def _find_policy(dataset_name: str) -> dict | None:
    """
    Two-tier lookup: an exact dataset_name match in 'policies' (the mutable,
    per-dataset policies created via POST/PUT/PATCH/DELETE /api/v1/policies)
    wins if present; otherwise falls back to a matching predefined prefix
    policy (see _find_prefix_policy). Returns None if neither matches —
    there's still no catch-all "default" policy.
    """
    policy = _collection.find_one({"dataset_name": dataset_name}, {"_id": 0})
    if policy is not None:
        return policy
    return _find_prefix_policy(dataset_name)


def get_dataset_policy(dataset_name: str) -> dict:
    """
    Returns the ABAC policy governing a dataset: exact dataset_name match if
    one exists, else the matching predefined prefix policy. A dataset with
    neither is a hard error. Used by both the background encryptor
    (functions.upload_to_encrypted_bucket) and the read/ABAC paths below, so
    a file dropped under a known prefix with no exact policy yet still
    auto-encrypts and is readable, exactly like one with an explicit policy.
    """
    policy = _find_policy(dataset_name)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No ABAC policy found for dataset '{dataset_name}'.",
        )
    return policy


def resolve_access(user_roles: list[str], dataset_name: str) -> str | None:
    """
    Finds a role the caller holds that this dataset's policy also grants.

    A dataset's policy lists the roles that qualify for access (any-of
    match — the caller needs at least one, not all of them). Returns any
    one matched role, or None if none qualify (including "dataset has no
    policy at all"). Which matched role is returned doesn't matter
    functionally — every qualifying role's wrapped DEK decrypts to the same
    plaintext — so the first match found while walking the caller's own
    role list is used as a simple, deterministic choice.
    """
    policy = _find_policy(dataset_name)
    if policy is None:
        return None

    granted = set(policy["policy"]["roles"])
    for role in user_roles:
        if role in granted:
            return role
    return None


def check_dataset_access(user_roles: list[str], dataset_name: str) -> bool:
    """
    Never raises — a dataset with no policy, or no qualifying role, simply
    isn't accessible (useful for list/filter callers).
    """
    return resolve_access(user_roles, dataset_name) is not None


def require_dataset_access(dataset_name: str, user_roles: list[str]) -> str:
    """
    Enforces the dataset-level ABAC policy. Raises 404 if the dataset has no
    policy at all, 403 if a policy exists but the caller doesn't qualify.
    Returns the matched role on success, so callers (e.g. decryption) don't
    need to re-resolve it.
    """
    matched_role = resolve_access(user_roles, dataset_name)
    if matched_role is not None:
        return matched_role
    if _find_policy(dataset_name) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No ABAC policy found for dataset '{dataset_name}'.",
        )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            f"Access denied for dataset '{dataset_name}'. "
            f"Your roles: {user_roles}"
        ),
    )
