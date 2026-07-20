# auth.py
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import settings

security = HTTPBearer()


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    FastAPI dependency that:
      1. Extracts the Bearer token from the Authorization header
      2. Verifies the signature using the RS256 public key
      3. Returns the decoded payload (claims)
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            settings.JWT_PUBLIC_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_aud": False},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
        )


def get_organizations(payload: dict = Depends(verify_token)) -> list[dict]:
    """
    Extracts the caller's organization grants from the token:
    [{"organizationId": "UBI", "access": "admin"}, ...]
    """
    return payload.get("organizations", [])


def get_caller(payload: dict = Depends(verify_token)) -> dict:
    """
    Extracts the caller's identity for audit logging: who they are, plus
    their organization grants in both the full and id-only forms callers
    typically need.
    """
    organizations = payload.get("organizations", [])
    return {
        "user_id": payload.get("sub", "unknown"),
        "username": payload.get("preferred_username", ""),
        "organizations": organizations,
        "org_ids": [o["organizationId"] for o in organizations],
    }
