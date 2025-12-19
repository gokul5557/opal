import requests
import json
import base64

OPA_URL = "http://localhost:8181/v1/data/policies/security/mfa"

def get_headers(email):
    # Simulate APISIX X-Userinfo header
    user_info = {"email": email}
    encoded = base64.b64encode(json.dumps(user_info).encode()).decode()
    return {
        "X-Userinfo": encoded
    }

def test_mfa(email, expected_required, expected_methods=None):
    print(f"Testing MFA for {email}...")
    
    payload = {
        "input": {
            "user": email
        }
    }
    
    print("\n[REQUEST]")
    print(json.dumps(payload, indent=2))
    
    try:
        response = requests.post(OPA_URL, json=payload)
        response.raise_for_status()
        full_response = response.json()
        
        print("\n[RESPONSE]")
        print(json.dumps(full_response, indent=2))
        
        result = full_response.get("result", {})
        config = result.get("config", {})
        
        required = config.get("required")
        methods = config.get("methods", [])
        
        print(f"\n[SUMMARY] Required={required}, Methods={methods}")
        
        if required != expected_required:
            print(f"  [FAIL] Expected Required={expected_required}, Got {required}")
            return
            
        if expected_methods:
            # Check if all expected methods are present (Set comparison)
            if set(expected_methods).issubset(set(methods)):
                print(f"  [PASS] Methods match/superset.")
            else:
                print(f"  [FAIL] Expected {expected_methods}, Got {methods}")
        else:
            print(f"  [PASS]")
            
    except Exception as e:
        print(f"  [ERROR] {e}")

if __name__ == "__main__":
    print("--- Running MFA Policy Verification ---")
    
    # gokul@sagasoft.io is in Org_1.
    # We assigned 'mfa': 'admins' to Org_1.
    # 'admins' policy requires MFA and allows [totp, email_otp].
    
    test_mfa("gokul@sagasoft.io", expected_required=True, expected_methods=["totp", "email_otp"])
    
    # Test a user who shouldn't have it (if any)
    # Alice is also in Org_1 so she will have it.
    # Let's create a hypothetical user "intern@sagasoft.io" via input injection?
    # No, they need to exist in data.json for 'inheritance' to work.
    # We'll stick to positive verification for now. 
