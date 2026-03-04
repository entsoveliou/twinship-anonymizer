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