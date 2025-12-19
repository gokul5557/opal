import requests
import json
import time
import base64

OPA_URL = "http://localhost:8181/v1/data"

def check_policy(num_orgs=10, users_per_org=10):
    total_users = num_orgs * users_per_org
    print(f"Starting Scale Test for {total_users} Users...")
    
    passed = 0
    failed = 0
    
    # Pre-fetch all users to avoid 100 individual calls if possible, or verify loading first
    response = requests.post(f"{OPA_URL}", json={"input": {}, "query": "data.policies.common.inheritance.users"})
    if response.status_code == 200:
        virtual_users = response.json().get("result", {}).get("result", [])
        # Format might vary depending on query type, let's assume raw count check
        count_response = requests.get(f"{OPA_URL}/policies/common/inheritance/users")
        if count_response.status_code == 200:
            count = len(count_response.json().get("result", {}))
            print(f"OPA Loaded Users Count: {count}")
            if count != total_users:
                 print(f"[WARN] Expected {total_users}, found {count}")
        
    for i in range(1, num_orgs + 1):
        org_id = f"Org_{i}"
        for u in range(1, users_per_org + 1):
            user_id = f"user_{u}@{org_id.lower()}.com"
            is_admin = (u == 1)
            
            # 1. Test APISIX Access
            # Admins (msp_admin / admin) should access /api/organization
            # Non-admins should access /api/my_account
            # Note: msp_admin has access to /api/organization via access_role_msp_admin
            # employee has access to /api/my_account via access_role_employee
            path = "/api/organization" if is_admin else "/api/my_account"
            
            # Construct Input
            user_info_json = json.dumps({
                "email": user_id,
                "org_id": org_id,
                "roles": ["msp_admin"] if is_admin else ["employee"]
            })
            # Rego expects Base64 encoded JSON in X-Userinfo
            user_info_b64 = base64.b64encode(user_info_json.encode("utf-8")).decode("utf-8")
            
            input_data = {
                "input": {
                    "request": {
                        "headers": {
                            "X-Userinfo": user_info_b64
                        },
                        "path": path
                    }
                }
            }
            
            # Check APISIX Allow
            # Note: We must query the specific rule: data.policies.apisix.policy.allow
            resp_apisix = requests.post(f"{OPA_URL}/policies/apisix/policy/allow", json=input_data)
            allow = resp_apisix.json().get("result", False)
            
            # DEBUG: Probe Explain Config
            if i == 1 and u == 1:
                debug_query = {
                    "query": 'data.policies.common.inheritance.explain_config("access")',
                    "input": { "user": user_id } 
                }
                debug_resp = requests.post(f"http://localhost:8181/v1/data", json=debug_query)
                print(f"[DEBUG] Explanation for {user_id}: {json.dumps(debug_resp.json(), indent=2)}")
                break # EXIT DEBUG
            
            # Check MFA
            # Check MFA
            resp_mfa = requests.post(f"{OPA_URL}/policies/security/mfa/config", json=input_data)
            mfa_config = resp_mfa.json().get("result", {})
            mfa_required = mfa_config.get("mfa_required", False)
            
            # Check Password Policy
            # Check effective password policy for user
            resp_pwd = requests.post(f"{OPA_URL}/policies/security/password/config", json=input_data)
            pwd_config = resp_pwd.json().get("result", {})
            min_len = pwd_config.get("password_min_length", 0)
            
            # Role Check (Implicit in Access)
            
            # Verification Logic
            user_passed = True
            
            # Access should be allowed for correct path
            if not allow:
                print(f"[FAIL] {user_id} denied access to {path}")
                user_passed = False
                
            # MFA Checks
            if is_admin and not mfa_required:
                print(f"[FAIL] {user_id} (Admin) MFA NOT required")
                user_passed = False
            if not is_admin and mfa_required:
                print(f"[FAIL] {user_id} (User) MFA unexpectedly required")
                user_passed = False
            
            # Hierarchy Override Check (Org 1 vs Others)
            if i == 1:
                # Org 1 has strict password override (20)
                if min_len != 20:
                    print(f"[FAIL] {user_id} (Org 1) expected pwd len 20, got {min_len}")
                    user_passed = False
            else:
                # Others inherit global default (10)
                if min_len != 10:
                    print(f"[FAIL] {user_id} (Org {i}) expected pwd len 10, got {min_len}")
                    user_passed = False
                
            if user_passed:
                passed += 1
            else:
                failed += 1
                
    print(f"\nTest Complete.")
    print(f"Total: {total_users}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")

if __name__ == "__main__":
    # Wait for container to be ready if called immediately
    # time.sleep(5) 
    check_policy()
