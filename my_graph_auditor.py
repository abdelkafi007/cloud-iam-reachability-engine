import boto3
from collections import deque


def initialise():

    iam = boto3.client(
        "iam",
        endpoint_url="http://127.0.0.1:5000",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1"
    )
    users = iam.list_users()["Users"]
    graph = {
        "ROOT_ADMIN": []
    }
    for u in users:
        username = u["UserName"]
        graph[username] = []
    
    return iam, graph

def populate_edges(iam, graph):
    ESCALATION_RULES = {
        "iam:CreateAccessKey": "TARGET_USER",
        "iam:CreateLoginProfile": "TARGET_USER",
        "iam:AttachUserPolicy": "SELF_ELEVATION",
        "iam:PutUserPolicy": "SELF_ELEVATION",
        "iam:AttachUserPolicy": "SELF_ELEVATION",
        "iam:PutUserPolicy": "SELF_ELEVATION"
    }      
    # Loop over every user in our graph
    for username in graph:
        if username == "ROOT_ADMIN":
            continue  # ROOT_ADMIN has no policies to inspect!
        attached_policy = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        for p in attached_policy:
            policyARN = p["PolicyArn"]
            policy_name = p["PolicyName"]
            version_info = iam.get_policy_version(PolicyArn=policyARN, VersionId="v1")
            statement = version_info["PolicyVersion"]["Document"]["Statement"]
            for s in statement:
                action = s.get("Action", "")
                resource = s.get("Resource", "")
                if isinstance(action, list):
                    actions = action
                else:
                    actions = [action]
                for act in actions:
                    if act == "*":
                        graph[username].append("ROOT_ADMIN")
                    elif ESCALATION_RULES.get(act) == "TARGET_USER":
                        target = resource.split(":user/")[1]
                        graph[username].append(target)
                    elif ESCALATION_RULES.get(act) == "SELF_ELEVATION":
                        graph[username].append("ROOT_ADMIN")
        # 1. Ask AWS what policies are attached to this username
        # (Hint: You already did this in security_auditor.py!)
        # attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
def find_attack_path(graph, start_user):
    todo = deque([start_user])
    visited = set([start_user])
    parents = {}

    while len(todo) > 0:
        current = todo.popleft()

        # 1. Target reached! Trace backwards using parents
        if current == "ROOT_ADMIN":
            path = [current]
            while current != start_user:
                current = parents[current]
                path.append(current)
            path.reverse()
            return path

        # 2. Look at who 'current' can compromise (graph[current])
        for neighbor in graph.get(current, []):
            if neighbor not in visited:
                visited.add(neighbor)
                parents[neighbor] = current
                todo.append(neighbor)

    # If queue is empty and we never found ROOT_ADMIN
    return None

if __name__ == "__main__":
    iam, graph = initialise()
    populate_edges(iam, graph)
    # At the bottom of your script:
    for user in graph:
        if user == "ROOT_ADMIN":
            continue   # Skip our target node!

        # Test THIS user!
        path = find_attack_path(graph, user)

        if path:
            # If the path has 2 nodes: ['bob', 'ROOT_ADMIN'] -> Direct Admin
            if len(path) == 2:
                print(f"[ DIRECT ADMIN] '{user}' has direct wildcard access to ROOT!")
                # If the path has 3+ nodes: ['charlie', 'admin', 'ROOT_ADMIN'] -> Chained Attack!
            else:
                print(f"[ PRIVILEGE ESCALATION] '{user}' can take over via: {' -> '.join(path)}")
        else:
            print(f"[ SAFE] '{user}' has no path to ROOT.")