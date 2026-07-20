# audit_router.py
from typing import Optional

from fastapi import APIRouter, Depends, Query

import audit
from auth import get_organizations

router = APIRouter(prefix="/api/v1/audit-logs", tags=["audit"])


@router.get("/")
def list_audit_logs(
    user_id: Optional[str] = Query(None, description="Filter by requesting user's JWT 'sub' claim"),
    organization: Optional[str] = Query(None, description="Filter by organizationId on the caller's token"),
    dataset_name: Optional[str] = Query(None, description="Filter by dataset name"),
    status: Optional[str] = Query(None, description="Filter by 'success' or 'failure'"),
    limit: int = Query(100, ge=1, le=1000),
    skip: int = Query(0, ge=0),
    _orgs: list = Depends(get_organizations),  # any valid JWT for now — no admin gate yet
):
    """
    Query the access audit log (getEncryptedFile / getUnencryptedFile attempts).
    No filters returns everyone's requests. Currently any authenticated
    caller can query any user_id/organization — there's no admin
    restriction yet, this is planned to be tightened later.
    """
    results = audit.query_access_logs(
        user_id=user_id,
        organization=organization,
        dataset_name=dataset_name,
        status=status,
        limit=limit,
        skip=skip,
    )
    return {"results": results, "count": len(results)}
