import json
import random
import boto3

iam = boto3.client(
    "iam",
    endpoint_url="http://127.0.0.1:5000",
    aws_access_key_id="test",
    aws_secret_access_key="test",
    region_name="us-east-1"
)

DEPARTMENTS = ["devops", "backend", "frontend", "data", "finance"]
COMMON_ACTIONS = {
    "devops": ["ec2:DescribeInstances", "ec2:StartInstances", "s3:GetObject"],
    "backend": ["s3:GetObject", "s3:PutObject", "sqs:ReceiveMessage"],
    "frontend": ["s3:GetObject", "cloudfront:CreateInvalidation"],
    "data": ["s3:GetObject", "s3:ListBucket", "glue:GetJob"],
    "finance": ["s3:GetObject", "budgets:ViewBudget"]
}

def setup_enterprise_iam():
    print("=== Provisioning Enterprise IAM Topology (100 Users) ===")
    
    # 1. Base Policies
    wildcard_policy = iam.create_policy(
        PolicyName="EnterpriseFullAdmin",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        })
    )["Policy"]["Arn"]

    standard_policy = iam.create_policy(
        PolicyName="StandardWorkerPolicy",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "ec2:DescribeInstances"],
                "Resource": "*"
            }]
        })
    )["Policy"]["Arn"]

    # 2. Main Admin
    iam.create_user(UserName="chief_admin")
    iam.attach_user_policy(UserName="chief_admin", PolicyArn=wildcard_policy)

    # 3. Intermediate Target (Lead Engineer)
    iam.create_user(UserName="lead_engineer")
    iam.attach_user_policy(UserName="lead_engineer", PolicyArn=wildcard_policy)

    # Escalation policy 1: Target chief_admin
    esc_to_chief = iam.create_policy(
        PolicyName="EscalateToChief",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:CreateAccessKey",
                "Resource": "arn:aws:iam::123456789012:user/chief_admin"
            }]
        })
    )["Policy"]["Arn"]

    # Escalation policy 2: Target lead_engineer
    esc_to_lead = iam.create_policy(
        PolicyName="EscalateToLead",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:CreateAccessKey",
                "Resource": "arn:aws:iam::123456789012:user/lead_engineer"
            }]
        })
    )["Policy"]["Arn"]

    # 4. Generate 90 Standard Users + 8 Over-Privileged + 2 Attackers
    created_users = ["chief_admin", "lead_engineer"]

    for i in range(1, 91):
        dept = random.choice(DEPARTMENTS)
        uname = f"{dept}_worker_{i:02d}"
        iam.create_user(UserName=uname)
        iam.attach_user_policy(UserName=uname, PolicyArn=standard_policy)
        created_users.append(uname)

    # 8 Over-privileged users (Given Full Admin, but only do minimal work)
    for i in range(1, 9):
        uname = f"overprivileged_dev_{i:02d}"
        iam.create_user(UserName=uname)
        iam.attach_user_policy(UserName=uname, PolicyArn=wildcard_policy)
        created_users.append(uname)

    # Attacker 1: intern_infiltrator -> lead_engineer -> chief_admin -> ROOT
    iam.create_user(UserName="intern_infiltrator")
    iam.attach_user_policy(UserName="intern_infiltrator", PolicyArn=esc_to_lead)
    created_users.append("intern_infiltrator")

    # Attacker 2: rogue_contractor -> chief_admin -> ROOT
    iam.create_user(UserName="rogue_contractor")
    iam.attach_user_policy(UserName="rogue_contractor", PolicyArn=esc_to_chief)
    created_users.append("rogue_contractor")

    print(f"Successfully provisioned {len(created_users)} enterprise users into AWS.")
    return created_users

def generate_enterprise_telemetry(users):
    print("=== Generating 3,000 Enterprise CloudTrail Telemetry Events ===")
    events = []
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

    # 1. Normal users generating routine traffic
    for _ in range(2800):
        u = random.choice(users)
        if u.startswith("overprivileged_"):
            # Overprivileged users only perform 1 or 2 harmless S3 actions!
            act = random.choice(["s3:GetObject", "s3:ListBucket"])
            target = "corp-data-lake/reports"
        elif u in ["intern_infiltrator", "rogue_contractor"]:
            act = "s3:GetObject"
            target = "public-assets/docs"
        else:
            dept = u.split("_")[0] if "_" in u else "backend"
            act = random.choice(COMMON_ACTIONS.get(dept, ["s3:GetObject"]))
            target = f"corp-{dept}-assets/task"

        hour = random.randint(8, 18)
        minute = random.randint(0, 59)
        day = random.choice(days)

        events.append({
            "identity": u,
            "action": act,
            "target": target,
            "time": f"{day} {hour:02d}:{minute:02d}"
        })

    # 2. Inject Attack 1: intern_infiltrator strikes on Thursday at 23:14
    events.append({
        "identity": "intern_infiltrator",
        "action": "iam:CreateAccessKey",
        "target": "arn:aws:iam::123456789012:user/lead_engineer",
        "time": "Thursday 23:14"
    })

    # 3. Inject Attack 2: rogue_contractor strikes on Friday at 03:40
    events.append({
        "identity": "rogue_contractor",
        "action": "iam:CreateAccessKey",
        "target": "arn:aws:iam::123456789012:user/chief_admin",
        "time": "Friday 03:40"
    })

    # Shuffle to simulate streaming arrival
    random.shuffle(events)

    with open("simulated_cloudtrail.json", "w", encoding="utf-8") as f:
        json.dump(events, f, indent=4)

    print(f"Successfully generated {len(events)} telemetry events into simulated_cloudtrail.json.")

if __name__ == "__main__":
    users = setup_enterprise_iam()
    generate_enterprise_telemetry(users)
