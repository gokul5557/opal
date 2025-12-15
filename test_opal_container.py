import requests
import json
import base64

# OPA running inside OPAL Client, exposed on port 8181
OPA_URL = "http://localhost:8181/v1/data/policies/apisix/policy"

def get_headers(email):
    # Simulate APISIX X-Userinfo header
    user_info = {"email": email}
    encoded = base64.b64encode(json.dumps(user_info).encode()).decode()
    return {
        "X-Userinfo": encoded
    }

def run_test(name, email, path, method="GET", ip="10.0.0.1", expected_allow=True):
    print(f"Testing {name}: {email} -> {method} {path}")
    
    payload = {
        "input": {
            "request": {
                "method": method,
                "path": path,
                "headers": get_headers(email)
            },
            # Simulate APISIX variable for IP
            "var": {
                "remote_addr": ip
            },
            # Common user field found in input root
            "user": email
        }
    }
    
    try:
        response = requests.post(OPA_URL, json=payload)
        response.raise_for_status()
        result = response.json().get("result", {})
        
        allowed = result.get("allow", False)
        reasons = result.get("deny", [])
        
        if allowed == expected_allow:
            print(f"  [PASS] Allowed: {allowed}")
        else:
            print(f"  [FAIL] Expected {expected_allow}, Got {allowed}")
            if reasons:
                print(f"  Deny Reasons: {reasons}")
                
    except Exception as e:
        print(f"  [ERROR] {e}")

if __name__ == "__main__":
    print("--- Testing OPAL Client (OPA) ---")
    
    # 1. Employee (should be allowed to /mail)
    run_test("Employee Mail Access", "gokul@sagasoft.io", "/mail/inbox")
    
    # 2. Employee (should be denied /admin)
    run_test("Employee Admin Access", "gokul@sagasoft.io", "/api/resource/Organization", expected_allow=False)
    
    # 3. Public Path (no auth)
    # Testing Public route requires different input structure in policy (no user),
    # but let's test a simple authenticated flow first for validation.
