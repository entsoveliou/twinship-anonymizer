# functions.py
from minio import Minio
from minio.error import S3Error
import io
import settings
import crypto_utils
import keys
from abac import get_dataset_policy


# Helper to get client (avoids repeating code)
def get_minio_client():
    return Minio(
        settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE
    )


def upload_to_encrypted_bucket(dataset_name, file_data_bytes) -> bool:
    """
    Receives raw file data, encrypts it with a fresh per-file DEK, wraps that
    DEK once per role granted in the dataset's ABAC policy, and
    uploads the encrypted content to the destination bucket. Datasets with no
    policy fail (logged, not processed) since there's no fallback — the
    caller is expected to retry on a later poll once a policy exists.

    Returns True on success, False on any failure (including "no policy
    yet") so the caller knows whether it's safe to consider this file done.
    """
    client = get_minio_client()
    dest_bucket = settings.DESTINATION_BUCKET

    try:
        if not client.bucket_exists(dest_bucket):
            client.make_bucket(dest_bucket)

        # No policy -> hard stop, nothing to encrypt against (raises HTTPException)
        policy = get_dataset_policy(dataset_name)
        roles = policy["policy"]["roles"]

        aad = dataset_name.encode()
        dek = crypto_utils.generate_dek()
        encrypted_bytes = crypto_utils.encrypt_content(file_data_bytes, dek, aad)

        print(f"Encrypting '{dataset_name}', wrapping DEK for {len(roles)} role(s)...")
        for role in roles:
            kek = keys.get_role_key(role)
            wrapped_dek = crypto_utils.wrap_key(kek, dek, aad)
            keys.store_wrapped_key(dataset_name, role, wrapped_dek)

        data_stream = io.BytesIO(encrypted_bytes)

        client.put_object(
            dest_bucket,
            dataset_name,
            data_stream,
            length=len(encrypted_bytes),
            content_type="application/octet-stream"
        )
        print(f"Successfully uploaded ENCRYPTED '{dataset_name}' to '{dest_bucket}'")
        return True

    except Exception as e:
        print(f"Error in upload_to_encrypted_bucket: {e}")
        return False


def delete_source_file(object_name):
    """
    Removes a file from the source (raw) bucket. Used once a file's encrypted
    copy is confirmed to exist — the raw copy has done its job.
    """
    client = get_minio_client()
    try:
        client.remove_object(settings.SOURCE_BUCKET, object_name)
        print(f"Deleted raw source copy of '{object_name}'")
    except Exception as e:
        print(f"Error deleting source file '{object_name}': {e}")


# --- NEW FUNCTIONS FOR API ---

def list_files_in_encrypted_bucket():
    """
    Returns a list of filenames present in the encrypted bucket.
    """
    client = get_minio_client()
    bucket = settings.DESTINATION_BUCKET

    if not client.bucket_exists(bucket):
        return []

    # list_objects returns an iterator
    objects = client.list_objects(bucket, recursive=True)

    # Extract just the names into a list
    file_list = [obj.object_name for obj in objects]
    return file_list


def list_files_in_bucket(bucket_name):
    """
    Returns a list of filenames present in any given bucket.
    """
    client = get_minio_client()

    if not client.bucket_exists(bucket_name):
        return []

    objects = client.list_objects(bucket_name, recursive=True)
    return [obj.object_name for obj in objects]


def download_file_from_encrypted_bucket(filename):
    """
    Downloads the raw bytes of a file from the encrypted bucket.
    Returns bytes or raises S3Error if not found.
    """
    client = get_minio_client()
    bucket = settings.DESTINATION_BUCKET

    try:
        response = client.get_object(bucket, filename)
        file_data = response.read()
        response.close()
        response.release_conn()
        return file_data
    except S3Error as e:
        # Re-raise so the API can handle the 404
        raise e


def file_exists_in_encrypted_bucket(dataset_name) -> bool:
    client = get_minio_client()
    try:
        client.stat_object(settings.DESTINATION_BUCKET, dataset_name)
        return True
    except S3Error:
        return False


def decrypt_dataset(dataset_name: str) -> bytes | None:
    """
    Decrypts a dataset's current encrypted content using ANY role's existing
    wrapped key — unlike getUnencryptedFile, this isn't answering "can this
    caller read it," it's "recover the plaintext so it can be re-encrypted
    against an updated policy." Returns None if that's not possible (no
    wrapped key on record, or unwrap/decrypt failure).
    """
    entry = keys.get_any_wrapped_entry(dataset_name)
    if entry is None:
        return None
    role, wrapped_dek = entry

    aad = dataset_name.encode()
    kek = keys.get_role_key(role)
    dek = crypto_utils.unwrap_key(kek, wrapped_dek, aad)
    if dek is None:
        return None

    encrypted_bytes = download_file_from_encrypted_bucket(dataset_name)
    return crypto_utils.decrypt_content(encrypted_bytes, dek, aad)


def reencrypt_dataset(dataset_name: str) -> bool:
    """
    Re-encrypts an already-encrypted dataset against its CURRENT policy —
    call this after a policy update changes an existing dataset's roles, so
    getUnencryptedFile doesn't break for added/changed roles. Decrypts with
    any existing wrapped key, discards the old wrapped-key entries (so
    removed roles don't leave dangling ones), and re-encrypts with a fresh
    DEK wrapped for every role in the now-current policy.

    Returns False (no-op) if the dataset was never encrypted in the first
    place — nothing to re-encrypt yet. Raises RuntimeError if the dataset
    WAS encrypted but re-encryption couldn't complete (e.g. decrypt
    failure) — this should be surfaced loudly, not swallowed, since it
    leaves the file stuck on stale key material until manually reprocessed.
    """
    if not file_exists_in_encrypted_bucket(dataset_name):
        return False

    plaintext = decrypt_dataset(dataset_name)
    if plaintext is None:
        raise RuntimeError(
            f"Could not decrypt '{dataset_name}' with its existing key material; re-encryption aborted."
        )

    keys.delete_dataset_keys(dataset_name)
    if not upload_to_encrypted_bucket(dataset_name, plaintext):
        raise RuntimeError(f"Re-encryption of '{dataset_name}' failed after policy update.")
    return True