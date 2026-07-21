# policies_router.py
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from pymongo.errors import DuplicateKeyError

import audit
import functions
from abac import _collection
from auth import get_caller

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


# --- Schemas ---

class PolicyBody(BaseModel):
    roles: list[str]

    @field_validator("roles")
    @classmethod
    def non_empty_list(cls, v):
        if not v:
            raise ValueError("must not be empty")
        return list(dict.fromkeys(v))  # de-dup, preserve order


class PolicyIn(BaseModel):
    dataset_name: str
    policy: PolicyBody


class PolicyOut(PolicyIn):
    owner: str
    created_at: datetime


class PolicyByUserTypeIn(BaseModel):
    dataset_name: str
    user_types: list[str]

    @field_validator("user_types")
    @classmethod
    def non_empty_list(cls, v):
        if not v:
            raise ValueError("must not be empty")
        return v


# Consortium "User-Role Type" -> granular resource roles it composites in
# Keycloak. Lets policies be created by type name instead of hand-typing the
# granular roles; the stored policy document is identical either way (a
# plain `policy.roles` list of granular strings) — nothing downstream needs
# to know this mapping exists.
USER_ROLE_TYPE_ROLES = {
    "UserGR": ["data-gr", "model-gr", "apps"],
    "UserST": ["data-st", "model-st", "apps"],
    "UserSL": ["data-sl", "model-sl", "apps"],
    "UserDM": ["data-gr", "data-st", "data-sl", "model-gr", "model-st"],
    "UserMA": ["model-gr", "model-st", "model-sl", "apps"],
    "UserAA": ["apps"],
    "UserDD": ["data-gr", "data-st", "data-sl"],
    "UserSU": ["data-gr", "data-st", "data-sl", "model-gr", "model-st", "model-sl", "apps"],
}


# --- Auth ---

def _require_role_overlap(caller_roles: list[str], required_roles: list[str], dataset_name: str):
    """
    Managing a dataset's policy requires holding at least one role that
    policy already grants (for create, before one exists yet, "already
    grants" means the roles being requested in the new policy body). No
    dedicated platform-admin concept — any role holder on a dataset can
    manage its policy.
    """
    if not any(r in required_roles for r in caller_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Access denied for dataset '{dataset_name}'. "
                f"Requires one of: {required_roles}. Your roles: {caller_roles}"
            ),
        )


# --- Helpers ---

def _to_out(doc: dict) -> dict:
    doc.pop("_id", None)
    return doc


def _not_found(dataset_name: str):
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Policy for dataset '{dataset_name}' not found.",
    )


def _roles_set(doc: dict | None) -> set:
    if not doc:
        return set()
    return set(doc["policy"]["roles"])


def _reencrypt_if_changed(dataset_name: str, old_doc: dict | None, new_doc: dict):
    """
    If this update actually changed the role grants, and the dataset is
    already encrypted, transparently re-encrypt it against the new policy
    (fresh DEK, re-wrapped for the current roles) so getUnencryptedFile
    doesn't break for added/changed roles. No-op if roles are unchanged or
    the dataset was never encrypted yet.
    """
    if _roles_set(old_doc) == _roles_set(new_doc):
        return
    try:
        functions.reencrypt_dataset(dataset_name)
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"Policy updated, but re-encryption failed: {e}. "
                f"The encrypted file is now out of sync with the new policy — "
                f"re-drop the source file to fix."
            ),
        )


# --- Endpoints ---

@router.get("/", response_model=list[PolicyOut])
def list_policies():
    """Return all policies."""
    return [_to_out(doc) for doc in _collection.find()]


@router.get("/{dataset_name}", response_model=PolicyOut)
def get_policy(dataset_name: str):
    """Return a single policy by dataset_name."""
    doc = _collection.find_one({"dataset_name": dataset_name})
    if doc is None:
        _not_found(dataset_name)
    return _to_out(doc)


@router.post(
    "/",
    response_model=PolicyOut,
    status_code=status.HTTP_201_CREATED,
)
def create_policy(policy: PolicyIn, caller: dict = Depends(get_caller)):
    """
    Create a new policy. Fails if dataset_name already exists. The caller
    must hold at least one of the roles being granted in the new policy.
    `owner` is server-set to the caller's user id, not caller-supplied.
    """
    def _log(result_status: str, reason: str = None):
        audit.log_access(
            caller["user_id"], caller["username"], caller["roles"],
            policy.dataset_name, "create_policy", result_status, reason,
        )

    _require_role_overlap(caller["roles"], policy.policy.roles, policy.dataset_name)

    doc = policy.model_dump()
    doc["owner"] = caller["user_id"]
    doc["created_at"] = datetime.now(timezone.utc)
    try:
        _collection.insert_one(doc)
    except DuplicateKeyError:
        reason = f"Policy for dataset '{policy.dataset_name}' already exists."
        _log("failure", reason)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=reason)
    _log("success")
    return _to_out(doc)


@router.post(
    "/by-user-type",
    response_model=PolicyOut,
    status_code=status.HTTP_201_CREATED,
)
def create_policy_by_user_type(body: PolicyByUserTypeIn, caller: dict = Depends(get_caller)):
    """
    Convenience creation path: specify consortium User-Role Type names
    (UserGR, UserSU, ...) instead of hand-typing granular roles. Expanded
    into the equivalent granular roles (deduped) via USER_ROLE_TYPE_ROLES,
    then created exactly like a normal policy through create_policy — same
    role-overlap check, same audit logging, same stored document shape.
    """
    def _log(result_status: str, reason: str = None):
        audit.log_access(
            caller["user_id"], caller["username"], caller["roles"],
            body.dataset_name, "create_policy", result_status, reason,
        )

    unknown = [t for t in body.user_types if t not in USER_ROLE_TYPE_ROLES]
    if unknown:
        reason = f"Unknown user type(s): {unknown}. Known types: {list(USER_ROLE_TYPE_ROLES)}"
        _log("failure", reason)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=reason)

    expanded_roles = list(dict.fromkeys(
        role for user_type in body.user_types for role in USER_ROLE_TYPE_ROLES[user_type]
    ))
    policy = PolicyIn(dataset_name=body.dataset_name, policy=PolicyBody(roles=expanded_roles))
    return create_policy(policy, caller)


@router.put(
    "/{dataset_name}",
    response_model=PolicyOut,
)
def update_policy(dataset_name: str, policy: PolicyIn, caller: dict = Depends(get_caller)):
    """
    Replace an existing policy entirely. Preserves the original owner and
    created_at. The caller must hold at least one role the EXISTING policy
    already grants. If the role grants change and the dataset is already
    encrypted, it's transparently re-encrypted against the new policy.
    """
    def _log(result_status: str, reason: str = None):
        audit.log_access(
            caller["user_id"], caller["username"], caller["roles"],
            dataset_name, "update_policy", result_status, reason,
        )

    existing = _collection.find_one({"dataset_name": dataset_name})
    if existing is None:
        reason = f"Policy for dataset '{dataset_name}' not found."
        _log("failure", reason)
        _not_found(dataset_name)

    try:
        _require_role_overlap(caller["roles"], existing["policy"]["roles"], dataset_name)
    except HTTPException as e:
        _log("failure", str(e.detail))
        raise

    doc = policy.model_dump()
    doc["dataset_name"] = dataset_name
    doc["owner"] = existing["owner"]
    doc["created_at"] = existing["created_at"]
    result = _collection.find_one_and_replace(
        {"dataset_name": dataset_name},
        doc,
        return_document=True,
    )
    try:
        _reencrypt_if_changed(dataset_name, existing, result)
    except HTTPException as e:
        _log("failure", str(e.detail))
        raise
    _log("success")
    return _to_out(result)


@router.patch(
    "/{dataset_name}",
    response_model=PolicyOut,
)
def patch_policy(dataset_name: str, updates: dict, caller: dict = Depends(get_caller)):
    """
    Partially update a policy (only supplied fields are changed). The
    caller must hold at least one role the EXISTING policy already grants.
    If the role grants change and the dataset is already encrypted, it's
    transparently re-encrypted against the new policy.
    """
    def _log(result_status: str, reason: str = None):
        audit.log_access(
            caller["user_id"], caller["username"], caller["roles"],
            dataset_name, "patch_policy", result_status, reason,
        )

    # Disallow changing server-controlled fields via patch
    updates.pop("dataset_name", None)
    updates.pop("owner", None)
    updates.pop("created_at", None)
    if not updates:
        reason = "No fields to update."
        _log("failure", reason)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=reason)

    existing = _collection.find_one({"dataset_name": dataset_name})
    if existing is None:
        reason = f"Policy for dataset '{dataset_name}' not found."
        _log("failure", reason)
        _not_found(dataset_name)

    try:
        _require_role_overlap(caller["roles"], existing["policy"]["roles"], dataset_name)
    except HTTPException as e:
        _log("failure", str(e.detail))
        raise

    result = _collection.find_one_and_update(
        {"dataset_name": dataset_name},
        {"$set": updates},
        return_document=True,
    )
    try:
        _reencrypt_if_changed(dataset_name, existing, result)
    except HTTPException as e:
        _log("failure", str(e.detail))
        raise
    _log("success")
    return _to_out(result)


@router.delete(
    "/{dataset_name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_policy(dataset_name: str, caller: dict = Depends(get_caller)):
    """Delete a policy. The caller must hold at least one role it already grants."""
    def _log(result_status: str, reason: str = None):
        audit.log_access(
            caller["user_id"], caller["username"], caller["roles"],
            dataset_name, "delete_policy", result_status, reason,
        )

    existing = _collection.find_one({"dataset_name": dataset_name})
    if existing is None:
        reason = f"Policy for dataset '{dataset_name}' not found."
        _log("failure", reason)
        _not_found(dataset_name)

    try:
        _require_role_overlap(caller["roles"], existing["policy"]["roles"], dataset_name)
    except HTTPException as e:
        _log("failure", str(e.detail))
        raise

    _collection.delete_one({"dataset_name": dataset_name})
    _log("success")
