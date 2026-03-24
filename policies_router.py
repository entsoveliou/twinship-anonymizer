# policies_router.py
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, field_validator
from pymongo.errors import DuplicateKeyError
from typing import Literal

from abac import _collection

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


# --- Schemas ---

class PolicyIn(BaseModel):
    filename: str
    required_roles: list[str]
    match: Literal["any", "all"]
    encryption_attributes: list[str]

    @field_validator("required_roles", "encryption_attributes")
    @classmethod
    def non_empty_list(cls, v):
        if not v:
            raise ValueError("must not be empty")
        return v


class PolicyOut(PolicyIn):
    pass


# --- Helpers ---

def _to_out(doc: dict) -> dict:
    doc.pop("_id", None)
    return doc


def _not_found(filename: str):
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Policy '{filename}' not found.",
    )


# --- Endpoints ---

@router.get("/", response_model=list[PolicyOut])
def list_policies():
    """Return all policies."""
    return [_to_out(doc) for doc in _collection.find()]


@router.get("/{filename}", response_model=PolicyOut)
def get_policy(filename: str):
    """Return a single policy by filename."""
    doc = _collection.find_one({"filename": filename})
    if doc is None:
        _not_found(filename)
    return _to_out(doc)


@router.post("/", response_model=PolicyOut, status_code=status.HTTP_201_CREATED)
def create_policy(policy: PolicyIn):
    """Create a new policy. Fails if filename already exists."""
    try:
        _collection.insert_one(policy.model_dump())
    except DuplicateKeyError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Policy '{policy.filename}' already exists.",
        )
    return policy.model_dump()


@router.put("/{filename}", response_model=PolicyOut)
def update_policy(filename: str, policy: PolicyIn):
    """Replace an existing policy entirely."""
    result = _collection.find_one_and_replace(
        {"filename": filename},
        policy.model_dump(),
        return_document=True,
    )
    if result is None:
        _not_found(filename)
    return _to_out(result)


@router.patch("/{filename}", response_model=PolicyOut)
def patch_policy(filename: str, updates: dict):
    """Partially update a policy (only supplied fields are changed)."""
    # Disallow changing the filename via patch
    updates.pop("filename", None)
    if not updates:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update.")

    result = _collection.find_one_and_update(
        {"filename": filename},
        {"$set": updates},
        return_document=True,
    )
    if result is None:
        _not_found(filename)
    return _to_out(result)


@router.delete("/{filename}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(filename: str):
    """Delete a policy. The 'default' policy cannot be deleted."""
    if filename == "default":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The 'default' policy cannot be deleted.",
        )
    result = _collection.delete_one({"filename": filename})
    if result.deleted_count == 0:
        _not_found(filename)
