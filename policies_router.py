# policies_router.py
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from pymongo.errors import DuplicateKeyError

import audit
import functions
from abac import _collection
from auth import get_caller

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


# --- Schemas ---

class RoleGrant(BaseModel):
    organizationId: str
    access: Literal["admin", "rw", "ro", "c-ro"]


class PolicyBody(BaseModel):
    roles: list[RoleGrant]

    @field_validator("roles")
    @classmethod
    def non_empty_list(cls, v):
        if not v:
            raise ValueError("must not be empty")
        return v


class PolicyIn(BaseModel):
    dataset_name: str
    owner: str
    policy: PolicyBody


class PolicyOut(PolicyIn):
    created_at: datetime


# --- Auth ---

def require_policy_write_access(caller: dict = Depends(get_caller)) -> dict:
    """
    Managing policies requires admin or rw access on at least one
    organization. This is a coarse starting gate; tighten to a dedicated
    platform-admin org/claim once that concept exists. Also doubles as the
    identity source for audit-logging policy writes, since it already
    resolves the caller.
    """
    if not any(o.get("access") in ("admin", "rw") for o in caller["organizations"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requires admin or rw access to manage policies.",
        )
    return caller


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
    return {(r["organizationId"], r["access"]) for r in doc["policy"]["roles"]}


def _reencrypt_if_changed(dataset_name: str, old_doc: dict | None, new_doc: dict):
    """
    If this update actually changed the role grants, and the dataset is
    already encrypted, transparently re-encrypt it against the new policy
    (fresh DEK, re-wrapped for the current roles) so getUnencryptedFile
    doesn't break for added/changed orgs. No-op if roles are unchanged or
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
def create_policy(policy: PolicyIn, caller: dict = Depends(require_policy_write_access)):
    """Create a new policy. Fails if dataset_name already exists."""
    def _log(result_status: str, reason: str = None):
        audit.log_access(
            caller["user_id"], caller["username"], caller["org_ids"],
            policy.dataset_name, "create_policy", result_status, reason,
        )

    doc = policy.model_dump()
    doc["created_at"] = datetime.now(timezone.utc)
    try:
        _collection.insert_one(doc)
    except DuplicateKeyError:
        reason = f"Policy for dataset '{policy.dataset_name}' already exists."
        _log("failure", reason)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=reason)
    _log("success")
    return _to_out(doc)


@router.put(
    "/{dataset_name}",
    response_model=PolicyOut,
)
def update_policy(dataset_name: str, policy: PolicyIn, caller: dict = Depends(require_policy_write_access)):
    """
    Replace an existing policy entirely. Preserves the original created_at.
    If the role grants change and the dataset is already encrypted, it's
    transparently re-encrypted against the new policy.
    """
    def _log(result_status: str, reason: str = None):
        audit.log_access(
            caller["user_id"], caller["username"], caller["org_ids"],
            dataset_name, "update_policy", result_status, reason,
        )

    existing = _collection.find_one({"dataset_name": dataset_name})
    doc = policy.model_dump()
    doc["dataset_name"] = dataset_name
    doc["created_at"] = existing["created_at"] if existing else datetime.now(timezone.utc)
    result = _collection.find_one_and_replace(
        {"dataset_name": dataset_name},
        doc,
        return_document=True,
    )
    if result is None:
        reason = f"Policy for dataset '{dataset_name}' not found."
        _log("failure", reason)
        _not_found(dataset_name)
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
def patch_policy(dataset_name: str, updates: dict, caller: dict = Depends(require_policy_write_access)):
    """
    Partially update a policy (only supplied fields are changed). If the
    role grants change and the dataset is already encrypted, it's
    transparently re-encrypted against the new policy.
    """
    def _log(result_status: str, reason: str = None):
        audit.log_access(
            caller["user_id"], caller["username"], caller["org_ids"],
            dataset_name, "patch_policy", result_status, reason,
        )

    # Disallow changing identity fields via patch
    updates.pop("dataset_name", None)
    updates.pop("created_at", None)
    if not updates:
        reason = "No fields to update."
        _log("failure", reason)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=reason)

    existing = _collection.find_one({"dataset_name": dataset_name})
    result = _collection.find_one_and_update(
        {"dataset_name": dataset_name},
        {"$set": updates},
        return_document=True,
    )
    if result is None:
        reason = f"Policy for dataset '{dataset_name}' not found."
        _log("failure", reason)
        _not_found(dataset_name)
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
def delete_policy(dataset_name: str, caller: dict = Depends(require_policy_write_access)):
    """Delete a policy."""
    def _log(result_status: str, reason: str = None):
        audit.log_access(
            caller["user_id"], caller["username"], caller["org_ids"],
            dataset_name, "delete_policy", result_status, reason,
        )

    result = _collection.delete_one({"dataset_name": dataset_name})
    if result.deleted_count == 0:
        reason = f"Policy for dataset '{dataset_name}' not found."
        _log("failure", reason)
        _not_found(dataset_name)
    _log("success")
