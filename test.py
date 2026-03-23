from minio import Minio
from minio.error import S3Error
import sys


def list_files_in_bucket(bucket_name):
    print(f"\nConnecting to MinIO to check bucket: '{bucket_name}'...")

    # Initialize the client with your credentials
    client = Minio(
        "minio-api.vessel-ai.eu",
        access_key="minioadmin",
        secret_key="minioadmin123",
        secure=True
    )

    try:
        # 1. Check if the bucket actually exists
        if not client.bucket_exists(bucket_name):
            print(f"❌ Error: Bucket '{bucket_name}' does not exist on the server.")
            return

        # 2. List the files
        print(f"\n--- Files inside '{bucket_name}' ---")

        # recursive=True ensures it looks inside any sub-folders as well
        objects = client.list_objects(bucket_name, recursive=True)

        file_count = 0
        for obj in objects:
            print(f"📄 {obj.object_name}")
            file_count += 1

        if file_count == 0:
            print("(The bucket is completely empty)")
        else:
            print(f"\n✅ Total files found: {file_count}")

    except S3Error as e:
        print(f"❌ MinIO API Error: {e}")
    except Exception as e:
        print(f"❌ General Error: {e}")


if __name__ == "__main__":
    # Check if a bucket name was passed via the command line
    if len(sys.argv) > 1:
        target_bucket = sys.argv[1]
    else:
        # Otherwise, ask the user to type it in
        target_bucket = input("Please enter the exact bucket name you want to check: ").strip()

    if target_bucket:
        list_files_in_bucket(target_bucket)
    else:
        print("No bucket name provided. Exiting.")