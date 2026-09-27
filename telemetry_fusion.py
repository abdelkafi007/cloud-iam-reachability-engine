import json
import boto3
from my_graph_auditor import initialise, populate_edges, find_attack_path

ESCALATION_RULES = {
    "iam:CreateAccessKey": "TARGET_USER",
    "iam:CreateLoginProfile": "TARGET_USER",
    "iam:AttachUserPolicy": "SELF_ELEVATION",
    "iam:PutUserPolicy": "SELF_ELEVATION"
}

with open("simulated_cloudtrail.json", "r", encoding="utf-8") as file:
    event = json.load(file)

def get_observed_actions(username):
    observed_actions = set()
    for v in event:
        if username == v["identity"]:
            observed_actions.add(v["action"])
    return observed_actions

def get_granted_actions(iam, username):
    action = set()
    attached_policy = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
    for p in attached_policy:
        policyARN = p["PolicyArn"]
        version_info = iam.get_policy_version(PolicyArn=policyARN, VersionId="v1")
        statement = version_info["PolicyVersion"]["Document"]["Statement"]
        for s in statement:
            raw_action = s.get("Action", "")
            if isinstance(raw_action, list):
                action.update(raw_action)
            elif isinstance(raw_action, str):
                action.add(raw_action)
    return action

def generate_recommended_policy(username, observed_actions):
    """
    Synthesizes a minimal least-privilege IAM policy based strictly
    on the user's observed telemetry and writes it to a JSON file.
    """
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": sorted(list(observed_actions)),
                "Resource": "*"
            }
        ]
    }
    filename = f"recommended_policy_{username}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=4)
    return filename

def audit_privilege_ratio(iam, username):
    granted = get_granted_actions(iam, username)
    observed = get_observed_actions(username)

    if not granted:
        return

    # Case 1: Wildcard root admin bloat (e.g. Bob)
    if "*" in granted or granted == {"*"}:
        if observed:
            print(f"[OVER-PRIVILEGED] User '{username}' has root '*' permissions but only uses: {observed}")
            filename = generate_recommended_policy(username, observed)
            print(f"   -> Synthesized minimal least-privilege policy saved to: {filename}")
        else:
            print(f"[DORMANT ACCOUNT] User '{username}' has root '*' permissions with zero observed activity.")
        return

    # Case 2: Standard threshold calculation (tau = 0.7)
    if len(granted) > 0:
        used_granted = observed.intersection(granted)
        ratio = len(used_granted) / len(granted)
        if ratio < 0.5:
            print(f"[THRESHOLD BREACH] User '{username}' utilization ratio is only {ratio:.1%} (< 50%)!")
            if observed:
                filename = generate_recommended_policy(username, observed)
                print(f"   -> Synthesized minimal least-privilege policy saved to: {filename}")

if __name__ == "__main__":
    iam, graph = initialise()
    populate_edges(iam, graph)

    print("\n=== Phase 1: Real-Time Escalation Threat Detection ===")
    for user in graph:
        if user == "ROOT_ADMIN":
            continue
        actions = get_observed_actions(user)
        for act in actions:
            if act in ESCALATION_RULES:
                path = find_attack_path(graph, user)
                if path and len(path) > 2:
                    print(f"[PRIVILEGE ESCALATION] '{user}' actively executed '{act}'! Attack Path: {' -> '.join(path)}")

    print("\n=== Phase 2: Over-Privilege & Least-Privilege Remediation ===")
    for user in graph:
        if user == "ROOT_ADMIN":
            continue
        audit_privilege_ratio(iam, user)