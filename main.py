# main.py
from fastapi import FastAPI, HTTPException, Response, Depends, Query
from fastapi.responses import StreamingResponse
from contextlib import asynccontextmanager
from minio import Minio
from minio.error import S3Error
import asyncio
import io
import jwt
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

# Custom Modules
import settings
import functions
import crypto_utils
import keys
import audit
from auth import get_roles, get_caller, verify_token
from abac import require_dataset_access, check_dataset_access
from policies_router import router as policies_router
from audit_router import router as audit_router

# --- MinIO Client Setup (For Background Monitor) ---
minio_client = Minio(
    settings.MINIO_ENDPOINT,
    access_key=settings.MINIO_ACCESS_KEY,
    secret_key=settings.MINIO_SECRET_KEY,
    secure=settings.MINIO_SECURE
)

processed_files = set()


# --- Background Task Logic (Encryption Monitor) ---

def check_if_exists_in_destination(object_name):
    try:
        minio_client.stat_object(settings.DESTINATION_BUCKET, object_name)
        return True
    except:
        return False


def process_file(object_name) -> bool:
    try:
        print(f"\n--- [PROCESSING]: {object_name} ---")
        response = minio_client.get_object(settings.SOURCE_BUCKET, object_name)
        content_bytes = response.read()
        response.close()
        response.release_conn()

        # Encrypt and Upload (logic is in functions.py)
        return functions.upload_to_encrypted_bucket(object_name, content_bytes)
    except Exception as e:
        print(f"Error processing file {object_name}: {e}")
        return False
    finally:
        print("-------------------------------------------\n")


def sync_existing_files():
    # Helper to avoid re-uploading files on restart
    if minio_client.bucket_exists(settings.DESTINATION_BUCKET):
        # We don't need asyncio.to_thread here because the parent function
        # (monitor_bucket) is already running this inside a thread!
        existing_files = functions.list_files_in_encrypted_bucket()
        for name in existing_files:
            processed_files.add(name)


async def monitor_bucket():
    await asyncio.to_thread(sync_existing_files)

    if not minio_client.bucket_exists(settings.SOURCE_BUCKET):
        try:
            minio_client.make_bucket(settings.SOURCE_BUCKET)
        except:
            pass

    while True:
        try:
            objects = await asyncio.to_thread(minio_client.list_objects, settings.SOURCE_BUCKET)
            for obj in list(objects):
                name = obj.object_name
                if name in processed_files:
                    # Already safely encrypted (this run or a previous one, e.g.
                    # a crash between upload and delete) — the raw copy's job
                    # is done.
                    await asyncio.to_thread(functions.delete_source_file, name)
                    continue

                exists = await asyncio.to_thread(check_if_exists_in_destination, name)
                if exists:
                    processed_files.add(name)
                    await asyncio.to_thread(functions.delete_source_file, name)
                else:
                    success = await asyncio.to_thread(process_file, name)
                    if success:
                        processed_files.add(name)
                        await asyncio.to_thread(functions.delete_source_file, name)
                    # else: no policy yet (or a transient error) — leave the
                    # raw file in place, it'll be retried on the next poll.
        except Exception as e:
            print(f"Monitor Error: {e}")
        await asyncio.sleep(settings.POLL_INTERVAL)


# --- Background Task Logic (Unpolicied-File Cleanup) ---

async def cleanup_unpolicied_files():
    """
    Parallel background task that deletes files from SOURCE_BUCKET that have
    sat with no matching ABAC policy for longer than POLICY_GRACE_SECONDS.
    Files that do have a policy are encrypted and removed by monitor_bucket
    itself, long before this would ever consider them — this only cleans up
    genuinely orphaned uploads (no policy ever created for them).
    """
    print(
        f"Starting unpolicied-file cleanup on bucket '{settings.SOURCE_BUCKET}' "
        f"(grace period: {settings.POLICY_GRACE_SECONDS}s)...")

    while True:
        try:
            if minio_client.bucket_exists(settings.SOURCE_BUCKET):
                objects = await asyncio.to_thread(minio_client.list_objects, settings.SOURCE_BUCKET)

                # MinIO returns last_modified in UTC, so we compare against UTC now
                now = datetime.now(timezone.utc)

                for obj in list(objects):
                    if obj.object_name in processed_files:
                        # Has (or will shortly have) an encrypted copy —
                        # monitor_bucket owns cleaning this one up.
                        continue

                    age_in_seconds = (now - obj.last_modified).total_seconds()

                    if age_in_seconds > settings.POLICY_GRACE_SECONDS:
                        print(
                            f"[CLEANUP] Deleting '{obj.object_name}' — no ABAC policy found "
                            f"within {settings.POLICY_GRACE_SECONDS}s (Age: {age_in_seconds:.1f}s)")
                        await asyncio.to_thread(minio_client.remove_object, settings.SOURCE_BUCKET, obj.object_name)

        except Exception as e:
            print(f"Cleanup Monitor Error: {e}")

        await asyncio.sleep(settings.POLL_INTERVAL)


# --- FastAPI App Definition & Lifespan ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start BOTH tasks concurrently
    task_monitor = asyncio.create_task(monitor_bucket())
    task_cleanup = asyncio.create_task(cleanup_unpolicied_files())

    yield

    # Cancel both tasks on shutdown
    task_monitor.cancel()
    task_cleanup.cancel()


app = FastAPI(lifespan=lifespan)
app.include_router(policies_router)
app.include_router(audit_router)


# --- Dev Token Endpoint (development only) ---

@app.post("/api/v1/dev/token")
async def issue_dev_token(
        sub: str = Query("dev-user", description="Subject (user id)"),
        preferred_username: str = Query("developer", description="Username"),
        email: str = Query("developer@example.com", description="Email claim"),
        roles: str = Query(
            "data-gr",
            description="Comma-separated realm role names, e.g. 'data-gr,model-gr,apps'",
        ),
        realm: str = Query("twinship", description="Realm name, shapes the 'iss' claim and default realm roles"),
        expires_in: int = Query(3600, description="Token lifetime in seconds"),
):
    """
    DEV ONLY — mints an RS256 JWT shaped exactly like a real Keycloak access
    token (same claim keys as a real partner-issued token: iss/aud/azp/sid/
    acr/allowed-origins/realm_access/resource_access/scope/email/etc.),
    signed with the local dev private key, so dev tokens are structurally
    interchangeable with production ones for testing. This endpoint 501s if
    no private key is configured, which is the production posture — a
    partner Keycloak issues real tokens instead, and only JWT_PUBLIC_KEY
    needs to change to verify them; the claim shape this app actually reads
    ('realm_access.roles') is identical either way. Every other claim here
    is cosmetic realism, not used for any authorization decision in this
    app (verify_token never enforces issuer/audience).
    """
    if not settings.JWT_PRIVATE_KEY:
        raise HTTPException(status_code=501, detail="No private key configured. This endpoint is for development only.")

    extra_roles = [r.strip() for r in roles.split(",") if r.strip()]

    now = datetime.now(timezone.utc)
    session_id = str(uuid.uuid4())

    payload = {
        "exp": now + timedelta(seconds=expires_in),
        "iat": now,
        "jti": str(uuid.uuid4()),
        "iss": f"http://localhost:8080/realms/{realm}",
        "aud": "account",
        "sub": sub,
        "typ": "Bearer",
        "azp": "twinship-anonymizer",
        "sid": session_id,
        "acr": "1",
        "allowed-origins": ["/*"],
        # The only claim this app actually authorizes against:
        "realm_access": {
            "roles": [f"default-roles-{realm}", "offline_access", "uma_authorization"] + extra_roles
        },
        "resource_access": {
            "account": {"roles": ["manage-account", "manage-account-links", "view-profile"]}
        },
        "scope": "openid profile email",
        "email_verified": True,
        "name": preferred_username,
        "preferred_username": preferred_username,
        "given_name": preferred_username,
        "family_name": "",
        "email": email,
    }
    token = jwt.encode(
        payload,
        settings.JWT_PRIVATE_KEY,
        algorithm=settings.JWT_ALGORITHM,
        headers={"kid": "dev-key-1", "typ": "JWT"},
    )
    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in}


# --- API V1 Endpoints (protected) ---

@app.get("/api/v1/verifyToken")
async def verify_jwt(payload: dict = Depends(verify_token)):
    """
    Returns whether the provided Bearer token is valid.
    verify_token raises 401 automatically on invalid/expired tokens,
    so reaching this point always means the token is valid.
    """
    return {"valid": True}



@app.get("/api/v1/listFiles")
async def list_files(roles: list[str] = Depends(get_roles)):
    """
    Returns a JSON array of file names in the encrypted bucket, filtered to
    those the caller holds a role for, per each dataset's policy.
    """
    try:
        all_files = functions.list_files_in_encrypted_bucket()
        accessible = [f for f in all_files if check_dataset_access(roles, f)]
        return {"files": accessible, "count": len(accessible)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/listFilesByBucket")
async def list_files_by_bucket(bucket: str = Query(..., description="Name of the bucket to list files from"), roles: list[str] = Depends(get_roles)):
    """
    Returns a JSON array of all file names in the specified bucket, filtered
    to those the caller holds a role for, per each dataset's policy.
    """
    try:
        all_files = functions.list_files_in_bucket(bucket)
        accessible = [f for f in all_files if check_dataset_access(roles, f)]
        return {"bucket": bucket, "files": accessible, "count": len(accessible)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/getUnencryptedFile")
def get_unencrypted_file(filename: str, caller: dict = Depends(get_caller)):
    """
    Downloads the file, decrypts it, and returns the clean content.
    Dataset ABAC: the caller must hold at least one role the dataset's
    policy grants. The matched role is then used directly to unwrap that
    role's copy of the DEK. Every attempt (success or failure) is written
    to the access audit log.
    """
    roles = caller["roles"]

    def _log(status: str, reason: str = None):
        audit.log_access(caller["user_id"], caller["username"], roles, filename, "getUnencryptedFile", status, reason)

    try:
        # 1. Check dataset-level ABAC (raises 404/403 if denied); returns the
        #    caller's matching role on this dataset.
        matched_role = require_dataset_access(filename, roles)

        # 2. Download raw encrypted bytes from MinIO
        encrypted_bytes = functions.download_file_from_encrypted_bucket(filename)

        # 3. Unwrap that role's copy of the DEK.
        wrapped_dek = keys.get_wrapped_key(filename, matched_role)
        if wrapped_dek is None:
            raise HTTPException(status_code=500, detail="No wrapped key found for this role/dataset.")

        aad = filename.encode()
        kek = keys.get_role_key(matched_role)
        dek = crypto_utils.unwrap_key(kek, wrapped_dek, aad)
        if dek is None:
            raise HTTPException(status_code=403, detail="Decryption Failed: Invalid attributes or corrupted key.")

        # 4. Decrypt the file content
        decrypted_bytes = crypto_utils.decrypt_content(encrypted_bytes, dek, aad)
        if decrypted_bytes is None:
            raise HTTPException(status_code=403, detail="Decryption Failed: Invalid attributes or corrupted data.")

        # 5. Return as a file download
        _log("success")
        return Response(
            content=decrypted_bytes,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except S3Error:
        _log("failure", "File not found in encrypted bucket")
        raise HTTPException(status_code=404, detail="File not found in encrypted bucket")
    except HTTPException as e:
        _log("failure", str(e.detail))
        raise
    except Exception as e:
        _log("failure", str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/getEncryptedFile")
def get_encrypted_file(filename: str, caller: dict = Depends(get_caller)):
    """
    Downloads the file and returns it AS IS (still encrypted) — mainly a way
    to confirm encryption actually happened. Access requirement is identical
    to getUnencryptedFile (same require_dataset_access call, no lower bar):
    this endpoint isn't a separate "ciphertext only" grant, it's a
    diagnostic view for callers who already qualify for real read access.
    Every attempt (success or failure) is written to the access audit log.
    """
    roles = caller["roles"]

    def _log(status: str, reason: str = None):
        audit.log_access(caller["user_id"], caller["username"], roles, filename, "getEncryptedFile", status, reason)

    try:
        # 1. Check dataset-level ABAC (raises 404/403 if denied)
        require_dataset_access(filename, roles)

        # 2. Download raw encrypted bytes from MinIO
        encrypted_bytes = functions.download_file_from_encrypted_bucket(filename)

        # 3. Return directly without decryption
        _log("success")
        return Response(
            content=encrypted_bytes,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}.enc"}
        )

    except S3Error:
        _log("failure", "File not found in encrypted bucket")
        raise HTTPException(status_code=404, detail="File not found in encrypted bucket")
    except HTTPException as e:
        _log("failure", str(e.detail))
        raise
    except Exception as e:
        _log("failure", str(e))
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)