# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run the application
python main.py

# Run via Docker Compose (includes MinIO)
docker-compose up

# Test MinIO connectivity
python test.py [bucket-name]
```

No formal test suite or lint configuration exists in this project.

## Architecture

This is a **secure file encryption service** built with FastAPI that:
1. Monitors a MinIO source bucket for new files
2. Encrypts them with AES-256-GCM and stores them in a destination bucket
3. Exposes authenticated endpoints to retrieve files (encrypted or decrypted)

### Module Responsibilities

- **`main.py`** — FastAPI app with 4 endpoints and 2 background async tasks (lifespan)
- **`functions.py`** — MinIO client creation and encrypted bucket operations (upload/list/download)
- **`auth.py`** — RS256 JWT verification via FastAPI dependency; extracts Keycloak-style `realm_access.roles`
- **`abac.py`** — Hardcoded per-dataset access policies (`DATASET_POLICIES`); `require_dataset_access()` raises 403
- **`crypto_utils.py`** — AES-256-GCM encrypt/decrypt; uses sorted JSON of role attributes as AAD (Additional Authenticated Data)
- **`settings.py`** — All config via environment variables with defaults

### Background Tasks (lifespan)

- **`monitor_bucket()`** — Polls `SOURCE_BUCKET` every `POLL_INTERVAL` seconds; encrypts new files and copies to `DESTINATION_BUCKET`; tracks processed files in-memory to avoid re-processing
- **`enforce_retention_policy()`** — Deletes files from `SOURCE_BUCKET` older than `RETENTION_SECONDS` matching `RETENTION_PREFIX`; cleans up the processed-files set accordingly

### API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/dev/token` | None | Issues dev JWT (disable in prod) |
| GET | `/api/v1/listFiles` | JWT | Lists files in destination bucket |
| GET | `/api/v1/getUnencryptedFile` | JWT + ABAC | Downloads and decrypts a file |
| GET | `/api/v1/getEncryptedFile` | JWT + ABAC | Downloads the raw `.enc` file |

### Encryption Design

Files are encrypted with AES-256-GCM. The **AAD** (Additional Authenticated Data) is the sorted JSON list of encryption attributes defined per-dataset in `abac.py`. This means decryption will fail if the wrong AAD is provided, binding decryption to the correct dataset policy.

The nonce is prepended to the ciphertext: `[12-byte nonce][ciphertext+tag]`.

### Authentication

Uses RS256 JWT. In development, keys are loaded from `dev_keys/private.pem` and `dev_keys/public.pem`. In production, `JWT_PUBLIC_KEY` env var should be set to the Keycloak public key.

### Key Configuration (environment variables)

| Variable | Purpose |
|----------|---------|
| `MINIO_ENDPOINT` | MinIO host |
| `SOURCE_BUCKET` | Unencrypted input bucket |
| `DESTINATION_BUCKET` | Encrypted output bucket |
| `RETENTION_SECONDS` | File age threshold for deletion |
| `RETENTION_PREFIX` | Prefix filter for retention policy |
| `POLL_INTERVAL` | Seconds between source bucket polls |
| `JWT_PUBLIC_KEY` | RS256 public key (production) |
