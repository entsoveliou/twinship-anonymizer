# main.py
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import StreamingResponse
from contextlib import asynccontextmanager
from minio import Minio
from minio.error import S3Error
import asyncio
import io

# Custom Modules
import settings
import functions
import crypto_utils

# --- MinIO Client Setup (For Background Monitor) ---
minio_client = Minio(
    settings.MINIO_ENDPOINT,
    access_key=settings.MINIO_ACCESS_KEY,
    secret_key=settings.MINIO_SECRET_KEY,
    secure=settings.MINIO_SECURE
)

processed_files = set()


# --- Background Task Logic ---

def check_if_exists_in_destination(object_name):
    try:
        minio_client.stat_object(settings.DESTINATION_BUCKET, object_name)
        return True
    except:
        return False


def process_file(object_name):
    try:
        print(f"\n--- [PROCESSING]: {object_name} ---")
        response = minio_client.get_object(settings.SOURCE_BUCKET, object_name)
        content_bytes = response.read()
        response.close()
        response.release_conn()

        # Encrypt and Upload (logic is in functions.py)
        functions.upload_to_encrypted_bucket(object_name, content_bytes)
        print("-------------------------------------------\n")
    except Exception as e:
        print(f"Error processing file {object_name}: {e}")


async def sync_existing_files():
    # Helper to avoid re-uploading files on restart
    if minio_client.bucket_exists(settings.DESTINATION_BUCKET):
        # We can use the new function here too!
        existing_files = await asyncio.to_thread(functions.list_files_in_encrypted_bucket)
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
                if obj.object_name not in processed_files:
                    # Double check logic
                    exists = await asyncio.to_thread(check_if_exists_in_destination, obj.object_name)
                    processed_files.add(obj.object_name)

                    if not exists:
                        await asyncio.to_thread(process_file, obj.object_name)
        except Exception as e:
            print(f"Monitor Error: {e}")
        await asyncio.sleep(settings.POLL_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(monitor_bucket())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan)


# --- API V1 Endpoints ---

@app.get("/api/v1/listFiles")
async def list_files():
    """
    Returns a JSON array of all file names in the encrypted bucket.
    """
    try:
        files = functions.list_files_in_encrypted_bucket()
        return {"files": files, "count": len(files)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/getUnencryptedFile")
async def get_unencrypted_file(filename: str):
    """
    Downloads the file, decrypts it using ABE attributes,
    and returns the clean file content.
    """
    try:
        # 1. Download raw encrypted bytes from MinIO (using functions.py)
        encrypted_bytes = functions.download_file_from_encrypted_bucket(filename)

        # 2. Define Attributes (Simulated ABE)
        # In a real scenario, these come from the authenticated user
        user_attributes = ['itsec', 'csirt', 'euisac']

        # 3. Decrypt (using crypto_utils.py)
        decrypted_bytes = crypto_utils.decrypt_data(encrypted_bytes, user_attributes)

        if decrypted_bytes is None:
            raise HTTPException(status_code=403, detail="Decryption Failed: Invalid attributes or corrupted data.")

        # 4. Return as a file download
        return Response(
            content=decrypted_bytes,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except S3Error:
        raise HTTPException(status_code=404, detail="File not found in encrypted bucket")
    except Exception as e:
        # If it's already an HTTPException, raise it, otherwise generic 500
        if isinstance(e, HTTPException): raise e
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/getEncryptedFile")
async def get_encrypted_file(filename: str):
    """
    Downloads the file and returns it AS IS (still encrypted).
    """
    try:
        # 1. Download raw encrypted bytes from MinIO (using functions.py)
        encrypted_bytes = functions.download_file_from_encrypted_bucket(filename)

        # 2. Return directly without decryption
        return Response(
            content=encrypted_bytes,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}.enc"}
        )

    except S3Error:
        raise HTTPException(status_code=404, detail="File not found in encrypted bucket")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)