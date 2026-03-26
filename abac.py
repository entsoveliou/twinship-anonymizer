# abac.py
from fastapi import HTTPException, status
from pymongo import MongoClient

import settings

_client = MongoClient(settings.MONGO_URI)
_collection = _client[settings.MONGO_DB]["policies"]
_prefix_collection = _client[settings.MONGO_DB]["prefix_policies"]


def get_dataset_policy(filename: str) -> dict:
    """
    Returns the ABAC policy for a filename using a three-step lookup:
      1. Exact match in 'policies' by filename
      2. Prefix match in 'prefix_policies' (first matching prefix wins)
      3. 'default' document in 'policies'
    """
    # 1. Exact match
    policy = _collection.find_one({"filename": filename}, {"_id": 0})
    if policy is not None:
        return policy

    # 2. Prefix match — fetch all prefix policies and check in Python
    #    (prefix list is expected to be small)
    for doc in _prefix_collection.find({}, {"_id": 0}):
        if filename.startswith(doc["prefix"]):
            return doc

    # 3. Default fallback
    policy = _collection.find_one({"filename": "default"}, {"_id": 0})
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No ABAC policy found in database.",
        )
    return policy


def check_dataset_access(user_roles: list[str], filename: str) -> bool:
    """
    Checks whether the user's roles satisfy the dataset's policy.
    """
    policy = get_dataset_policy(filename)
    required = set(policy["required_roles"])
    user = set(user_roles)

    if policy["match"] == "all":
        return required.issubset(user)
    else:
        return bool(required & user)


def get_dataset_encryption_attributes(filename: str) -> list[str]:
    """
    Returns the encryption attributes (AAD) for a dataset.
    These are needed for both encryption and decryption.
    """
    policy = get_dataset_policy(filename)
    return policy["encryption_attributes"]


def require_dataset_access(filename: str, user_roles: list[str]):
    """
    Enforces the dataset-level ABAC policy. Raises 403 if denied.
    """
    if not check_dataset_access(user_roles, filename):
        policy = get_dataset_policy(filename)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Access denied for dataset '{filename}'. "
                f"Requires {policy['match']} of {policy['required_roles']}. "
                f"Your roles: {user_roles}"
            ),
        )
