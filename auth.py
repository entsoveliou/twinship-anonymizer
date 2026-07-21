# auth.py
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import settings

security = HTTPBearer()

# Keycloak infrastructure roles that show up in every token regardless of
# what the caller is actually entitled to — they never match a dataset
# policy, so filtering them out is purely for audit-log/debugging
# cleanliness, not correctness.
_INFRA_ROLES = {"offline_access", "uma_authorization"}


def _is_infra_role(role: str) -> bool:
    return role in _INFRA_ROLES or role.startswith("default-roles-")


def _extract_roles(payload: dict) -> list[str]:
    """
    Extracts the caller's meaningful realm roles from realm_access.roles,
    filtering out Keycloak infrastructure roles. Consortium "User-Role Type"
    roles (e.g. UserSU) are NOT filtered — they pass through like any other
    role, they just won't happen to match any dataset policy since policies
    reference resource-shaped role names (data-gr, model-st, apps, ...).
    """
    raw = payload.get("realm_access", {}).get("roles", [])
    return [r for r in raw if not _is_infra_role(r)]


def _candidate_public_keys() -> list[str]:
    # Tried in order: the configured partner/Keycloak key first, then the
    # bundled dev key — so real tokens and locally-minted dev tokens both
    # verify, regardless of whether a partner key is configured.
    return [k for k in (settings.JWT_PUBLIC_KEY, settings.DEV_JWT_PUBLIC_KEY) if k]


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    FastAPI dependency that:
      1. Extracts the Bearer token from the Authorization header
      2. Verifies the signature against each configured public key in turn
         (partner Keycloak key, then the dev key) until one matches
      3. Returns the decoded payload (claims)
    """
    token = credentials.credentials
    candidates = _candidate_public_keys()
    if not candidates:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No JWT verification key configured.",
        )

    last_error: Exception | None = None
    for public_key in candidates:
        try:
            return jwt.decode(
                token,
                public_key,
                algorithms=[settings.JWT_ALGORITHM],
                options={"verify_aud": False},
            )
        except jwt.ExpiredSignatureError:
            # Signature matched this key, so this IS the right issuer — the
            # token is just expired. No point trying other candidate keys.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
            )
        except jwt.InvalidTokenError as e:
            last_error = e
            continue

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"Invalid token: {last_error}",
    )


def get_roles(payload: dict = Depends(verify_token)) -> list[str]:
    """Extracts the caller's realm roles from the token (see _extract_roles)."""
    return _extract_roles(payload)


def get_caller(payload: dict = Depends(verify_token)) -> dict:
    """Extracts the caller's identity for audit logging: who they are, plus their realm roles."""
    return {
        "user_id": payload.get("sub", "unknown"),
        "username": payload.get("preferred_username", ""),
        "roles": _extract_roles(payload),
    }
