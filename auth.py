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


def get_roles(payload: dict = Depends(verify_token)) -> list[str]:
    """
    Extracts the roles list from the decoded token.
    Supports Keycloak's nested realm_access.roles and a flat 'roles' claim.
    """
    # Keycloak standard location
    roles = payload.get("realm_access", {}).get("roles")
    if roles is None:
        # Fallback: flat 'roles' claim (used by dev token endpoint)
        roles = payload.get("roles", [])
    return roles
