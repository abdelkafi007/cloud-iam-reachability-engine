import json

events = [
    # --- Alice: Routine daily S3 workflow ---
    {
        "identity": "alice",
        "action": "s3:GetObject",
        "target": "vault/confidential.pdf",
        "time": "monday 09:00"
    },
    {
        "identity": "alice",
        "action": "s3:PutObject",
        "target": "vault/work.pdf",
        "time": "monday 12:00"
    },
    {
        "identity": "alice",
        "action": "s3:GetObject",
        "target": "vault/tasklist.pdf",
        "time": "tuesday 09:00"
    },
    {
        "identity": "alice",
        "action": "s3:PutObject",
        "target": "vault/workdone.pdf",
        "time": "tuesday 17:00"
    },
    {
        "identity": "alice",
        "action": "s3:GetObject",
        "target": "vault/tasklist.pdf",
        "time": "wednesday 09:00"
    },
    {
        "identity": "alice",
        "action": "s3:PutObject",
        "target": "vault/workdone.pdf",
        "time": "wednesday 17:00"
    },

    # --- Bob: Routine reader (has Admin rights, but only reads S3!) ---
    {
        "identity": "bob",
        "action": "s3:ListBucket",
        "target": "vault",
        "time": "monday 10:30"
    },
    {
        "identity": "bob",
        "action": "s3:GetObject",
        "target": "vault/readme.txt",
        "time": "monday 11:00"
    },
    {
        "identity": "bob",
        "action": "s3:ListBucket",
        "target": "vault",
        "time": "tuesday 14:00"
    },
    {
        "identity": "bob",
        "action": "s3:GetObject",
        "target": "vault/guidelines.pdf",
        "time": "wednesday 10:15"
    },

    # --- Charlie: Innocent at first, then strikes on Wednesday night ---
    {
        "identity": "charlie",
        "action": "s3:GetObject",
        "target": "vault/readme.txt",
        "time": "monday 11:30"
    },
    {
        "identity": "charlie",
        "action": "s3:GetObject",
        "target": "vault/tasklist.pdf",
        "time": "tuesday 10:00"
    },
    {
        "identity": "charlie",
        "action": "iam:CreateAccessKey",
        "target": "arn:aws:iam::123456789012:user/admin",
        "time": "wednesday 23:30"
    }
]

with open("simulated_cloudtrail.json", "w", encoding="utf-8") as file:
    json.dump(events, file, indent=4)

print(f"Successfully generated {len(events)} telemetry events into simulated_cloudtrail.json")
