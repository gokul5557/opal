import json
import requests
import base64
import fnmatch
import os
import glob
from typing import Dict, List, Any

# Configuration
OPA_URL = "http://localhost:8182/v1/data/mail_service/apisix/allow"
GLOBAL_DATA_PATH = "policy_data/global/data.json"
ORGS_DIR = "policy_data/organizations"

# ANSI Colors
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def load_json(path):
    with open(path, 'r') as f:
        return json.load(f)

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
        if not role_def:
            continue
            
        policy_name = role_def["assigned_policies"]["access"]
        policy_def = global_policies["global_policies"]["access"].get(policy_name)
        
        if policy_def and match_permission(path, method, policy_def["api_permissions"]):
             return True
             
    return False

def extract_apis_from_policy(global_data):
    apis = set()
    access_policies = global_data["global_policies"]["access"]
    for policy in access_policies.values():
        for pattern in policy["api_permissions"].keys():
            test_path = pattern.replace("*", "test_resource_123")
            apis.add(test_path)
    return sorted(list(apis))

def main():
    print(f"{Colors.BOLD}Starting Policy Verification (Multi-Tenant)...{Colors.RESET}")
    
    try:
        global_data = load_json(GLOBAL_DATA_PATH)
    except Exception as e:
        print(f"Error loading global data: {e}")
        return

    test_apis = extract_apis_from_policy(global_data)
    methods = ["GET", "POST", "DELETE"]
    
    org_files = glob.glob(os.path.join(ORGS_DIR, "*", "data.json"))
    
    total_tests = 0
    passed_tests = 0

    print(f"Loaded Global Data. Identified {len(test_apis)} API paths to test.")
    print(f"Found {len(org_files)} organizations to test: {[os.path.basename(os.path.dirname(f)) for f in org_files]}")
    print("-" * 140)
    print(f"{'Org':<20} | {'User':<25} | {'Role':<10} | {'Method':<6} | {'Path':<40} | {'Exp':<5} | {'Act':<5} | {'Result'}")
    print("-" * 140)

    for org_path in sorted(org_files):
        try:
            org_data = load_json(org_path)
            users = org_data.get("users", {})
            org_name = os.path.basename(os.path.dirname(org_path))
            
            for email, user_info in users.items():
                roles = user_info.get("roles", [])
                
                for path in test_apis:
                    for method in methods:
                        total_tests += 1
                        expected = get_expected_result(roles, path, method, global_data)
                        header_val = create_user_header(email)
                        input_payload = {
                            "input": {
                                "request": {
                                    "method": method,
                                    "path": path,
                                    "headers": {
                                        "X-Userinfo": header_val
                                    }
                                }
                            }
                        }
                        
                        try:
                            resp = requests.post(OPA_URL, json=input_payload)
                            actual = resp.json().get("result", False)
                        except Exception as e:
                            print(f"OPA Request Failed: {e}")
                            actual = "ERR"

                        is_pass = (expected == actual)
                        if is_pass:
                            passed_tests += 1
                        
                        res_str = f"{Colors.GREEN}PASS{Colors.RESET}" if is_pass else f"{Colors.RED}FAIL{Colors.RESET}"
                        exp_str = "ALLOW" if expected else "DENY"
                        act_str = "ALLOW" if actual else "DENY"
                        
                        role_str = ",".join(roles)
                        print(f"{org_name:<20} | {email:<25} | {role_str:<10} | {method:<6} | {path:<40} | {exp_str:<5} | {act_str:<5} | {res_str}")
        except Exception as e:
            print(f"Error processing {org_path}: {e}")

    print("-" * 140)
    success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
    print(f"{Colors.BOLD}Final Result: {passed_tests}/{total_tests} passed ({success_rate:.1f}%){Colors.RESET}")

if __name__ == "__main__":
    main()
