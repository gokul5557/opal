import json
import requests
import base64
import fnmatch
import os
import glob
from typing import Dict, List, Any

# Configuration
OPA_URL = "http://localhost:8181/v1/data/mail_service/apisix/allow"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GLOBAL_DATA_PATH = os.path.join(BASE_DIR, "../policy_data/global/data.json")
ORGS_DIR = os.path.join(BASE_DIR, "../policy_data/organizations")

def create_user_header(email: str) -> str:
    payload = json.dumps({"email": email})
    return base64.b64encode(payload.encode()).decode()

def match_permission(path: str, method: str, permissions: Dict[str, List[str]]) -> bool:
    actions = []
    if method in ["GET", "HEAD", "OPTIONS"]: actions.append("read")
    if method in ["POST", "PUT", "PATCH", "DELETE"]: actions.append("write")
    if method == "POST": actions.append("create")
    if method in ["PUT", "PATCH"]: actions.append("update")
    if method == "DELETE": actions.append("delete")

    for pattern, allowed_actions in permissions.items():
        if fnmatch.fnmatch(path, pattern):
            for act in actions:
                if act in allowed_actions:
                    return True
    return False

def get_expected_result(user_roles: List[str], path: str, method: str, global_policies: Dict) -> bool:
    global_roles = global_policies.get("global_roles", {})
    for role in user_roles:
        role_def = global_roles.get(role)
        if not role_def: continue
        policy_name = role_def["assigned_policies"]["access"]
        policy_def = global_policies["global_policies"]["access"].get(policy_name)
        if policy_def and match_permission(path, method, policy_def["api_permissions"]):
             return True
    return False

def run_tests_for_org(org_id: str):
    results = []
    try:
        with open(GLOBAL_DATA_PATH, 'r') as f:
            global_data = json.load(f)
    except:
        return {"error": "Global data not found"}

    # Extract test APIs
    test_apis = set()
    access_policies = global_data["global_policies"]["access"]
    for policy in access_policies.values():
        for pattern in policy["api_permissions"].keys():
            test_apis.add(pattern.replace("*", "test_resource"))
    
    test_apis = sorted(list(test_apis))
    methods = ["GET", "POST", "DELETE"]
    
    org_path = os.path.join(ORGS_DIR, org_id, "data.json")
    if not os.path.exists(org_path):
        return {"error": f"Org data for {org_id} not found"}

    try:
        with open(org_path, 'r') as f:
            org_data = json.load(f)
        users = org_data.get("users", {})
        
        for email, user_info in users.items():
            roles = user_info.get("roles", [])
            for path in test_apis:
                for method in methods:
                    expected = get_expected_result(roles, path, method, global_data)
                    header_val = create_user_header(email)
                    payload = {"input": {"request": {"method": method, "path": path, "headers": {"X-Userinfo": header_val}}}}
                    
                    try:
                        resp = requests.post(OPA_URL, json=payload, timeout=2)
                        actual = resp.json().get("result", False)
                    except:
                        actual = "Error"

                    results.append({
                        "user": email,
                        "method": method,
                        "path": path,
                        "expected": "ALLOW" if expected else "DENY",
                        "actual": "ALLOW" if actual == True else ("DENY" if actual == False else "ERR"),
                        "passed": expected == actual
                    })
    except Exception as e:
        return {"error": str(e)}

    return results
