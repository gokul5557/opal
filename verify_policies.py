import json
import base64
import requests
import fnmatch
from typing import Dict, List, Any

# Configuration
OPA_URL = "http://localhost:8181/v1/data/mail_service/apisix/allow"
GLOBAL_DATA_PATH = "mail_service/policy_data/global/data.json"
ORG_DATA_PATH = "mail_service/policy_data/organizations/Company_ABC/data.json"

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
    # Create simple JSON payload
    payload = json.dumps({"email": email})
    # Base64 encode
    return base64.b64encode(payload.encode()).decode()

def match_permission(path: str, method: str, permissions: Dict[str, List[str]]) -> bool:
    """ Python implementation of the Rego matching logic """
    # Map method to actions (same as Rego)
    actions = []
    if method in ["GET", "HEAD", "OPTIONS"]: actions.append("read")
    if method in ["POST", "PUT", "PATCH", "DELETE"]: actions.append("write")
    if method == "POST": actions.append("create")
    if method in ["PUT", "PATCH"]: actions.append("update")
    if method == "DELETE": actions.append("delete")

    for pattern, allowed_actions in permissions.items():
        # Check glob match
        # Fnmatch checks if filename matches pattern. We need to check if PATH matches PATTERN.
        # But Rego glob.match(pattern, ["/"], path) handles hierarchy. 
        # For simplicity, we assume standard shell globbing here which is close.
        if fnmatch.fnmatch(path, pattern):
            # Check if any action matches
            for act in actions:
                if act in allowed_actions:
                    return True
    return False

def get_expected_result(user_roles: List[str], path: str, method: str, global_policies: Dict) -> bool:
    """ Determine if access should be allowed based on roles """
    # Simplification: Assume roles map directly to global policy names for now
    # In real data, user -> role -> assigned_policies -> access policy name
    
    # We need the global roles definition to map "admin" -> "global_admin_access"
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
    """ Extract a list of distinct APIs to test from the policy definitions """
    apis = set()
    # Extract from all access policies to get a good coverage list
    access_policies = global_data["global_policies"]["access"]
    for policy in access_policies.values():
        for pattern in policy["api_permissions"].keys():
            # If pattern is a wildcard like /api/v1/users/*, we make a concrete test path
            test_path = pattern.replace("*", "test_resource_123")
            apis.add(test_path)
    return sorted(list(apis))

def main():
    print(f"{Colors.BOLD}Starting Policy Verification...{Colors.RESET}")
    
    # 1. Load Data
    try:
        global_data = load_json(GLOBAL_DATA_PATH)
        org_data = load_json(ORG_DATA_PATH)
    except Exception as e:
        print(f"Error loading data files: {e}")
        return

    users = org_data.get("users", {})
    # Use extracted APIs or a defined list? Let's use extracted to be dynamic.
    test_apis = extract_apis_from_policy(global_data)
    
    # Common methods to test
    methods = ["GET", "POST", "DELETE"]

    results = []
    
    print(f"Loaded {len(users)} users and identified {len(test_apis)} API paths to test.")
    print("-" * 120)
    print(f"{'User':<25} | {'Role':<10} | {'Method':<6} | {'Path':<40} | {'Exp':<5} | {'Act':<5} | {'Result'}")
    print("-" * 120)

    total_tests = 0
    passed_tests = 0

    for email, userers_info in users.items():
        roles = userers_info.get("roles", [])
        
        for path in test_apis:
            for method in methods:
                total_tests += 1
                
                # 1. Calculate Expected
                expected = get_expected_result(roles, path, method, global_data)
                
                # 2. Call OPA
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

                # 3. Compare
                is_pass = (expected == actual)
                if is_pass:
                    passed_tests += 1
                
                # Formatting
                res_str = f"{Colors.GREEN}PASS{Colors.RESET}" if is_pass else f"{Colors.RED}FAIL{Colors.RESET}"
                exp_str = "ALLOW" if expected else "DENY"
                act_str = "ALLOW" if actual else "DENY"
                
                role_str = ",".join(roles)
                
                print(f"{email:<25} | {role_str:<10} | {method:<6} | {path:<40} | {exp_str:<5} | {act_str:<5} | {res_str}")

    print("-" * 120)
    success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
    print(f"{Colors.BOLD}Final Result: {passed_tests}/{total_tests} passed ({success_rate:.1f}%){Colors.RESET}")

if __name__ == "__main__":
    main()
