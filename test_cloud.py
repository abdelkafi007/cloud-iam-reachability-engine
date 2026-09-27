import boto3

# Connect to your local AWS cloud running in Docker
iam = boto3.client(
    "iam",
    endpoint_url="http://127.0.0.1:5000",
    aws_access_key_id="test",
    aws_secret_access_key="test",
    region_name="us-east-1"
)

s3 = boto3.client(
    "s3",
    endpoint_url="http://127.0.0.1:5000",
    aws_access_key_id="test",
    aws_secret_access_key="test",
    region_name="us-east-1"
)

def main():
    print("=== 1. Inspecting Cloud Users (IAM) ===")
    users = iam.list_users()["Users"]
    for u in users:
        print(f"User: {u['UserName']} | ARN: {u['Arn']}")

    print("\n=== 2. Inspecting Cloud Storage Buckets (S3) ===")
    buckets = s3.list_buckets()["Buckets"]
    for b in buckets:
        print(f"Bucket: {b['Name']} | Created: {b['CreationDate']}")

if __name__ == "__main__":
    main()
