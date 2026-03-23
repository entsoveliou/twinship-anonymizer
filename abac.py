# abac.py
from fastapi import HTTPException, status


# --- Hardcoded per-dataset ABAC policies ---
# Each dataset defines:
#   - required_roles: roles the user must have to access this dataset
#   - match: "any" (at least one role) or "all" (every role)
#   - encryption_attributes: the attributes used for encryption/decryption (AAD)
#
# If no specific policy exists, DEFAULT_DATASET_POLICY is used.

DATASET_POLICIES = {
    "dataset1.pdf": {
        "required_roles": ["itsec", "csirt", "admin"],
        "match": "all",
        "encryption_attributes": ["itsec", "csirt", "euisac"],
    },
    "dataset2.pdf": {
        "required_roles": ["itsec", "admin"],
        "match": "any",
        "encryption_attributes": ["itsec", "csirt"],
    },
    "dataset3.pdf": {
        "required_roles": ["csirt", "admin"],
        "match": "any",
        "encryption_attributes": ["csirt", "euisac"],
    },
}

DEFAULT_DATASET_POLICY = {
    "required_roles": ["developer", "operator"],
    "match": "all",
    "encryption_attributes": ["itsec", "csirt", "euisac"],
}


def get_dataset_policy(filename: str) -> dict:
    """
    Returns the ABAC policy for a specific dataset.
    Falls back to DEFAULT_DATASET_POLICY if no specific rule exists.
    """
    return DATASET_POLICIES.get(filename, DEFAULT_DATASET_POLICY)


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
