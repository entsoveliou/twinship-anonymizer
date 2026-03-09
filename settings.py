import os

# --- MinIO Connection Settings ---
# We use os.getenv to allow overriding via actual environment variables,
# but provide your requested values as defaults.
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio-api.twinship.epu.ntua.gr")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin123")
# Set to True for HTTPS
MINIO_SECURE = True

# --- Bucket Settings ---
SOURCE_BUCKET = os.getenv("SOURCE_BUCKET", "demo-data")
DESTINATION_BUCKET = os.getenv("DESTINATION_BUCKET", "encrypted-files")

# --- App Configuration ---
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", 5)) # Seconds

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

JWT_PUBLIC_KEY = os.getenv("JWT_PUBLIC_KEY", _default_public_key)
# Private key is ONLY used by the dev token endpoint — never in production
JWT_PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY", _default_private_key)