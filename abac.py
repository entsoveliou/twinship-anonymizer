# abac.py
from fastapi import HTTPException, status
from pymongo import MongoClient

import settings

_client = MongoClient(settings.MONGO_URI)
_collection = _client[settings.MONGO_DB]["policies"]


def _find_policy(dataset_name: str) -> dict | None:
    return _collection.find_one({"dataset_name": dataset_name}, {"_id": 0})


def get_dataset_policy(dataset_name: str) -> dict:
    """
    Returns the ABAC policy for a dataset by exact dataset_name match.
    There is no prefix matching and no default fallback: a dataset without
    an explicit policy is a hard error. Create the policy before the dataset
    shows up.
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
