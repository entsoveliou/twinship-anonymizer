# prefix_policies_router.py
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, field_validator
from pymongo.errors import DuplicateKeyError
from typing import Literal

from abac import _prefix_collection

router = APIRouter(prefix="/api/v1/prefix-policies", tags=["prefix-policies"])


# --- Schemas ---

class PrefixPolicyIn(BaseModel):
    prefix: str
    required_roles: list[str]
    match: Literal["any", "all"]
    encryption_attributes: list[str]

    @field_validator("required_roles", "encryption_attributes")
    @classmethod
    def non_empty_list(cls, v):
        if not v:
            raise ValueError("must not be empty")
        return v


class PrefixPolicyOut(PrefixPolicyIn):
    pass


# --- Helpers ---

def _to_out(doc: dict) -> dict:
    doc.pop("_id", None)
    return doc


def _not_found(prefix: str):
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Prefix policy '{prefix}' not found.",
    )


# --- Endpoints ---

@router.get("/", response_model=list[PrefixPolicyOut])
def list_prefix_policies():
    """Return all prefix policies."""
    return [_to_out(doc) for doc in _prefix_collection.find()]


@router.get("/{prefix}", response_model=PrefixPolicyOut)
def get_prefix_policy(prefix: str):
    """Return a single prefix policy."""
    doc = _prefix_collection.find_one({"prefix": prefix})
    if doc is None:
        _not_found(prefix)
    return _to_out(doc)


@router.post("/", response_model=PrefixPolicyOut, status_code=status.HTTP_201_CREATED)
def create_prefix_policy(policy: PrefixPolicyIn):
    """Create a new prefix policy. Fails if prefix already exists."""
    try:
        _prefix_collection.insert_one(policy.model_dump())
    except DuplicateKeyError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Prefix policy '{policy.prefix}' already exists.",
        )
    return policy.model_dump()


@router.put("/{prefix}", response_model=PrefixPolicyOut)
def update_prefix_policy(prefix: str, policy: PrefixPolicyIn):
    """Replace an existing prefix policy entirely."""
    result = _prefix_collection.find_one_and_replace(
        {"prefix": prefix},
        policy.model_dump(),
        return_document=True,
    )
    if result is None:
        _not_found(prefix)
    return _to_out(result)


@router.patch("/{prefix}", response_model=PrefixPolicyOut)
def patch_prefix_policy(prefix: str, updates: dict):
    """Partially update a prefix policy."""
    updates.pop("prefix", None)
    if not updates:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update.")

    result = _prefix_collection.find_one_and_update(
        {"prefix": prefix},
        {"$set": updates},
        return_document=True,
    )
    if result is None:
        _not_found(prefix)
    return _to_out(result)


@router.delete("/{prefix}", status_code=status.HTTP_204_NO_CONTENT)
def delete_prefix_policy(prefix: str):
    """Delete a prefix policy."""
    result = _prefix_collection.delete_one({"prefix": prefix})
    if result.deleted_count == 0:
        _not_found(prefix)
