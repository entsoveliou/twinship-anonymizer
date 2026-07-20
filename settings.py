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

# In production, set JWT_PUBLIC_KEY env var to the Keycloak realm public key (PEM format).
# For development, the key is loaded from dev_keys/public.pem.
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


# `or` (not getenv's default arg) so an env var present-but-blank — e.g. from
# an env_file line like "JWT_PUBLIC_KEY=" — still falls back to the dev key,
# instead of silently becoming an empty, unusable key.
JWT_PUBLIC_KEY = _normalize_pem(os.getenv("JWT_PUBLIC_KEY") or _default_public_key)
# Private key is ONLY used by the dev token endpoint — never in production
JWT_PRIVATE_KEY = _normalize_pem(os.getenv("JWT_PRIVATE_KEY") or _default_private_key)