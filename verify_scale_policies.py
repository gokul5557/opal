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
            # Admins (msp_admin / admin) should access /admin or similar
            # Non-admins should access /mail
            path = "/admin" if is_admin else "/mail"
            
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
            
            # DEBUG: Probe extraction
            if i == 1 and u == 1:
                debug_email_resp = requests.post(f"{OPA_URL}/policies/apisix/policy/user_email", json=input_data)
                with open("debug_extraction.log", "w") as f:
                    f.write(f"X-Userinfo B64: {user_info_b64}\n")
                    f.write(f"Extracted Email: {debug_email_resp.text}\n")
                break # EXIT DEBUG
            
            # Check MFA
            # Check MFA
            resp_mfa = requests.post(f"{OPA_URL}/policies/security/mfa/config", json=input_data)
            mfa_config = resp_mfa.json().get("result", {})
            mfa_required = mfa_config.get("mfa_required", False)
            
            # Role Check (Implicit in Access)
            
            # Verification Logic
            user_passed = True
            
            # Access should be allowed for correct path
            if not allow:
                print(f"[FAIL] {user_id} denied access to {path}")
                user_passed = False
                
            # MFA: Admins should require MFA (based on Global Policy / Org Assignment)
            # Org_1...10 all use "password": "default" and "mfa": "admins" (from generator)
            # So u==1 (admin) => MFA True. u!=1 => MFA False.
            if is_admin and not mfa_required:
                print(f"[FAIL] {user_id} (Admin) MFA NOT required")
                user_passed = False
            if not is_admin and mfa_required:
                print(f"[FAIL] {user_id} (User) MFA unexpectedly required")
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
