import requests
import json
import sys

BASE_URL = "http://localhost:8182/api/test"

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

def run_test(name, endpoint, payload, expected_status, expected_content_check=None):
    print(f"{BOLD}Test: {name}{RESET}")
    try:
        if endpoint == "password":
            url = f"{BASE_URL}/password"
            # Password endpoint EXPECTS Form Data (based on app.py analysis)
            response = requests.post(url, data=payload)
        else:
            url = f"{BASE_URL}/access"
            # Access endpoint expects Form Data
            response = requests.post(url, data=payload)
            
        status_match = response.status_code == expected_status
        content_match = True
        
        if expected_content_check:
            content_match = expected_content_check(response.json())
            
        if status_match and content_match:
            print(f"  {GREEN}PASS{RESET}")
            return True
        else:
            print(f"  {RED}FAIL{RESET}")
            print(f"  Expected Status: {expected_status}, Got: {response.status_code}")
            if expected_content_check:
                print(f"  Content Check Failed. Got: {json.dumps(response.json(), indent=2)}")
            return False
            
    except Exception as e:
        print(f"  {RED}ERROR{RESET}: {e}")
        return False

def check_denied(data):
    # For password, returns dict of reasons (should be non-empty)
    # For access, returns {"allowed": False, ...}
    if "allowed" in data:
        return data["allowed"] is False
    return len(data) > 0 # Password denial reasons exist

def check_allowed(data):
    # For password, returns {} (empty reasons)
    # For access, returns {"allowed": True, ...}
    if "allowed" in data:
        return data["allowed"] is True
    return len(data) == 0 # Password denial reasons empty

def main():
    print(f"{BOLD}=== Starting Comprehensive Policy Verification ==={RESET}\n")
    results = []

    # -------------------------------------------------------------------------
    # 1. Password Policy Tests
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}--- Password Policy Tests ---{RESET}")
    
    # Alice (Engineering, Org_1) -> High Security (Min 12, Special, Upper, etc.)
    user_high = "alice@sagasoft.io"
    
    results.append(run_test(
        "Password_High_TooShort", "password",
        {"user": user_high, "password": "Short1!"},
        200, check_denied # Expected Deny
    ))
    
    results.append(run_test(
        "Password_High_NoSpecial", "password",
        {"user": user_high, "password": "LongPassword123"},
        200, check_denied # Expected Deny
    ))

    results.append(run_test(
        "Password_High_Valid", "password",
        {"user": user_high, "password": "SecurePassword123!"},
        200, check_allowed # Expected Allow
    ))

    # user_64587 (HR, Org_1) -> Medium Security (Min 10, Number, No Special Required)
    # Wait, 'gokul' policy assigned to HR department? Let's check data.json
    # HR assigned 'gokul' (Min 11, Special).
    # Sales assigned 'Org_1_Pwd_Low' (Min 8).
    # Let's use a hypothetical Sales user if we can find one, or just trust Alice.
    
    # -------------------------------------------------------------------------
    # 2. APISIX Access Policy Tests
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}--- APISIX Access Policy Tests ---{RESET}")

    # Alice (Org_1, Engineering)
    # Allowed IP: 10.0.0.0/8 (from Org_1_IP_White)
    # Allowed Paths: /mail, /drive, / (Workspace Admin role)
    
    results.append(run_test(
        "Access_Valid_User_IP_Path", "access",
        {"user": user_high, "ip": "10.0.0.1", "path": "/mail", "method": "GET"},
        200, check_allowed
    ))

    results.append(run_test(
        "Access_Invalid_IP", "access",
        {"user": user_high, "ip": "192.168.1.1", "path": "/mail", "method": "GET"},
        200, check_denied
    ))

    # User with Restricted Access
    # user_64587 (HR, Employee Role) -> Access to /mail, /drive (via employee_apps role?)
    # or just Department/Group policies?
    # Let's test a generic path they shouldn't have, e.g. /admin
    user_hr = "user_64587@org_1.com"
    
    results.append(run_test(
        "Access_Restricted_Path", "access",
        {"user": user_hr, "ip": "10.0.0.1", "path": "/admin", "method": "GET"},
        200, check_denied
    ))
    
    results.append(run_test(
        "Access_Valid_Path_HR", "access",
        {"user": user_hr, "ip": "10.0.0.1", "path": "/mail/mail.api.mail.create_mail", "method": "POST"},
        200, check_allowed # Assuming employee_apps role provides this
    ))

    # -------------------------------------------------------------------------
    # 3. Cross-Org Isolation
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}--- Cross-Org Isolation Tests ---{RESET}")
    # Org 2 User
    user_org2 = "user_59185@org_2.com"
    # Org 2 IP Whitelist: 0.0.0.0/0 (Any) for 'Org_2_IP_Any' assigned to Org_2
    
    # Password
    results.append(run_test(
        "Org2_Password_High_Valid", "password",
        {"user": user_org2, "password": "SecurePassword123!"},
        200, check_allowed
    ))

    # Access
    # Org 2 Access Policy: Org_2_Access_User -> /app, /home
    results.append(run_test(
        "Org2_Access_Valid", "access",
        {"user": user_org2, "ip": "1.2.3.4", "path": "/app", "method": "GET"},
        200, check_allowed
    ))
    
    results.append(run_test(
        "Org2_Access_Invalid", "access",
        {"user": user_org2, "ip": "1.2.3.4", "path": "/admin", "method": "GET"},
        200, check_denied
    ))
    

    # Summary
    print(f"\n{BOLD}=== Summary ==={RESET}")
    passed = results.count(True)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print(f"{GREEN}ALL TESTS PASSED{RESET}")
        sys.exit(0)
    else:
        print(f"{RED}SOME TESTS FAILED{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
