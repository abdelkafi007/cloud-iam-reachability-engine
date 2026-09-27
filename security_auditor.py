import boto3

iam = boto3.client(
    "iam",
    endpoint_url="http://127.0.0.1:5000",
    aws_access_key_id="test",
    aws_secret_access_key="test",
    region_name="us-east-1"
)

def main():
    print("=== 1. Inspecting Cloud Users (IAM) ===")
    response = iam.list_users()
    users = response["Users"]

    for u in users:
        username = u["UserName"]
        attached_policy = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        if not attached_policy:
            print(f"  [-] no policies attached for '{username}'")
        for p in attached_policy:
            policyARN = p["PolicyArn"]
            policy_name = p["PolicyName"]
            version_info = iam.get_policy_version(PolicyArn=policyARN, VersionId="v1")
            statement = version_info["PolicyVersion"]["Document"]["Statement"]
            for s in statement:
                action = s.get("Action", "")
                if action == "*" or "*" in action:
                    print(f"user '{username}' has wildcard '*' ")
                else:
                    print(f"the user '{username}' is safe")


if __name__ == "__main__":
    main()