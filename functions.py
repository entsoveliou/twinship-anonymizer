# functions.py
from minio import Minio
from minio.error import S3Error
import io
import settings
from crypto_utils import encrypt_data


# Helper to get client (avoids repeating code)
def get_minio_client():
    return Minio(
        settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE
    )


def upload_to_encrypted_bucket(object_name, file_data_bytes):
    """
    Receives raw file data, ENCRYPTS it based on attributes,
    and uploads to the destination bucket.
    """
    client = get_minio_client()
    dest_bucket = settings.DESTINATION_BUCKET

    try:
        if not client.bucket_exists(dest_bucket):
            client.make_bucket(dest_bucket)

        # Attributes used for encryption
        attributes = ['itsec', 'csirt', 'euisac']

        print(f"Encrypting '{object_name}' with attributes: {attributes}...")
        encrypted_bytes = encrypt_data(file_data_bytes, attributes)

        data_stream = io.BytesIO(encrypted_bytes)

        client.put_object(
            dest_bucket,
            object_name,
            data_stream,
            length=len(encrypted_bytes),
            content_type="application/octet-stream"
        )
        print(f"Successfully uploaded ENCRYPTED '{object_name}' to '{dest_bucket}'")

    except Exception as e:
        print(f"Error in upload_to_encrypted_bucket: {e}")


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