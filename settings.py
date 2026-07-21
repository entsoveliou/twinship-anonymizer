import os

# --- MinIO Connection Settings ---
# We use os.getenv to allow overriding via actual environment variables,
# but provide your requested values as defaults.
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio-api.vessel-ai.eu")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin123")
# How long a file may sit in SOURCE_BUCKET with no matching ABAC policy
# before it's deleted as orphaned (see cleanup_unpolicied_files in main.py).
POLICY_GRACE_SECONDS = int(os.getenv("POLICY_GRACE_SECONDS", 60))
# Set MINIO_SECURE=false for HTTP-only MinIO deployments (e.g. local/dev)
MINIO_SECURE = os.getenv("MINIO_SECURE", "true").strip().lower() in ("1", "true", "yes")

# --- Bucket Settings ---
SOURCE_BUCKET = os.getenv("SOURCE_BUCKET", "demo-data")
DESTINATION_BUCKET = os.getenv("DESTINATION_BUCKET", "encrypted-files")

# --- App Configuration ---
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", 5)) # Seconds

# --- MongoDB Configuration ---
MONGO_URI = os.getenv("MONGO_URI", "mongodb://root:rootpassword@localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "datasetPolicies")

# --- JWT / Auth Configuration ---
JWT_ALGORITHM = "RS256"

# Set JWT_PUBLIC_KEY env var to the partner Keycloak realm's public key (PEM
# format) to verify real tokens. The dev keypair in dev_keys/ is separate and
# unrelated to Keycloak's own keys — it's only ever used to sign/verify
# tokens minted by the local /api/v1/dev/token endpoint.
_default_public_key = ""
_default_private_key = ""
try:
    with open(os.path.join(os.path.dirname(__file__), "dev_keys", "public.pem")) as f:
        _default_public_key = f.read()
    with open(os.path.join(os.path.dirname(__file__), "dev_keys", "private.pem")) as f:
        _default_private_key = f.read()
except FileNotFoundError:
    pass

def _normalize_pem(value: str) -> str:
    # .env files can't hold real newlines, so PEM values are commonly passed
    # with literal "\n" escapes. A real PEM never contains that literal
    # two-character sequence otherwise, so unescaping it is always safe.
    return value.replace("\\n", "\n") if value else value


# The partner/Keycloak-issued verification key, if configured — empty string
# if unset. No fallback here (unlike before): dev-token verification is
# handled separately by DEV_JWT_PUBLIC_KEY below, so auth.verify_token can
# accept tokens signed by EITHER key at once, rather than only whichever one
# this variable happens to hold.
JWT_PUBLIC_KEY = _normalize_pem(os.getenv("JWT_PUBLIC_KEY") or "")
# Always loaded from the bundled dev keypair (if present) so tokens minted by
# /api/v1/dev/token keep verifying even after JWT_PUBLIC_KEY is set to a real
# partner key.
DEV_JWT_PUBLIC_KEY = _normalize_pem(_default_public_key)
# Private key is ONLY used by the dev token endpoint — never in production
JWT_PRIVATE_KEY = _normalize_pem(os.getenv("JWT_PRIVATE_KEY") or _default_private_key)