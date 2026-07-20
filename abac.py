# abac.py
from fastapi import HTTPException, status
from pymongo import MongoClient

import settings
from crypto_utils import TIER_ORDER

_client = MongoClient(settings.MONGO_URI)
_collection = _client[settings.MONGO_DB]["policies"]

# TIER_ORDER is highest -> lowest ("admin", "rw", "ro", "c-ro"); rank it so
# higher access = higher number, for simple >= comparisons.
TIER_RANK = {tier: len(TIER_ORDER) - 1 - i for i, tier in enumerate(TIER_ORDER)}


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


def get_org_access(dataset_name: str, organization_id: str) -> str | None:
    """Returns the access tier granted to a specific org on a dataset, if any."""
    policy = get_dataset_policy(dataset_name)
    for r in policy["policy"]["roles"]:
        if r["organizationId"] == organization_id:
            return r["access"]
    return None


def resolve_access(user_orgs: list[dict], dataset_name: str) -> str | None:
    """
    Finds an organization the caller can use to access this dataset.

    The bar is always exactly what the policy recorded for that org — never
    a separate hardcoded floor. A caller's token carries a per-org access
    claim (their own clearance within that org); the policy carries a
    per-org access grant (what tier that org is entitled to on this
    dataset). The caller qualifies only if their own claimed tier meets or
    exceeds what their org was granted — a lower personal clearance than
    your org's grant doesn't let you exercise that grant. If multiple orgs
    qualify, the one with the caller's highest claimed tier wins (relevant
    for which org's wrapped key gets used to decrypt).

    Returns the matched organizationId, or None if no org qualifies
    (including "dataset has no policy at all").
    """
    policy = _find_policy(dataset_name)
    if policy is None:
        return None

    granted = {r["organizationId"]: r["access"] for r in policy["policy"]["roles"]}

    best_org = None
    best_rank = -1
    for o in user_orgs:
        org_id = o.get("organizationId")
        user_tier = o.get("access")
        policy_tier = granted.get(org_id)
        if policy_tier is None:
            continue
        user_rank = TIER_RANK.get(user_tier, -1)
        if user_rank < TIER_RANK.get(policy_tier, len(TIER_RANK)):
            continue  # caller's own clearance doesn't meet what their org was granted
        if user_rank > best_rank:
            best_rank = user_rank
            best_org = org_id

    return best_org


def check_dataset_access(user_orgs: list[dict], dataset_name: str) -> bool:
    """
    Never raises — a dataset with no policy, or no qualifying org, simply
    isn't accessible (useful for list/filter callers).
    """
    return resolve_access(user_orgs, dataset_name) is not None


def require_dataset_access(dataset_name: str, user_orgs: list[dict]) -> str:
    """
    Enforces the dataset-level ABAC policy. Raises 404 if the dataset has no
    policy at all, 403 if a policy exists but the caller doesn't qualify.
    Returns the matched organizationId on success, so callers (e.g.
    decryption) don't need to re-resolve it.
    """
    matched_org = resolve_access(user_orgs, dataset_name)
    if matched_org is not None:
        return matched_org
    if _find_policy(dataset_name) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No ABAC policy found for dataset '{dataset_name}'.",
        )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            f"Access denied for dataset '{dataset_name}'. "
            f"Your organizations: {user_orgs}"
        ),
    )
