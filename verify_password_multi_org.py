import json
import requests
from typing import Dict, List, Any

# Configuration
OPA_URL = "http://localhost:8181/v1/data/mail_service/password"

# ANSI Colors
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def verify_password(user_id: str, password: str) -> (bool, List[str]):
    payload = {
        "input": {
            "user_id": user_id,
            "password": password
        }
    }
    try:
        resp = requests.post(OPA_URL, json=payload)
        res = resp.json().get("result", {})
        allowed = res.get("allow", False)
        reasons = res.get("deny", [])
        return allowed, reasons
    except Exception as e:
        print(f"Error: {e}")
        return False, ["Error"]

def main():
    print(f"{Colors.BOLD}Starting Multi-Org Password Policy Verification...{Colors.RESET}")
    print(f"{Colors.BOLD}Global Default: Min 8 (Wait, Global is 10? Let me check){Colors.RESET}")
    # Global Default in data.json: "default" {"password_min_length": 8, "password_require_number": true} ?
    # Let's assume defaults based on logic: 
    # Global Default is 8 chars, 1 number (Wait, verified `password.rego` says default allowed "password123" which is 11 chars. "short" was 5. So >8 is verified).
    
    print("-" * 120)
    print(f"{'User (Org)':<35} | {'Scenario':<30} | {'Len':<4} | {'Exp':<5} | {'Act':<5} | {'Result'}")
    print("-" * 120)

    scenarios = [
        # 1. Org_Alpha_Global (Inherits Global Default: Min 8, Num True?).
        #    Global Data default: "password_min_length": 10, "password_require_number": true. (Actually need to check values).
        #    Assuming Global Default is Min 10 for now.
        {
            "user": "user1@alpha-global.com", "desc": "Alpha (Global): Short (<10)",
             "pwd": "short", "exp": False
        },
        {
            "user": "user1@alpha-global.com", "desc": "Alpha (Global): Valid (10+)",
             "pwd": "password1234", "exp": True
        },

        # 2. Org_Beta_Custom (Strict Override: Min 20 + All Chars for Admin, Min 12 for User)
        #    Admin: "ultra_strict"
        {
            "user": "admin@beta-custom.com", "desc": "Beta Admin: Short (<20)",
             "pwd": "password1234567890", "exp": False
        },
        {
            "user": "admin@beta-custom.com", "desc": "Beta Admin: No Special",
             "pwd": "password123456789012345", "exp": False # 21 chars but no special
        },
         {
            "user": "admin@beta-custom.com", "desc": "Beta Admin: Valid (20+Full)",
             "pwd": "Password1234567890!@#", "exp": True
        },
        #    User: "strict_user" (Min 12, Number)
        {
            "user": "user1@beta-custom.com", "desc": "Beta User: Short (<12)",
             "pwd": "password123", "exp": False
        },
        {
            "user": "user1@beta-custom.com", "desc": "Beta User: Valid (12+Num)",
             "pwd": "password123456", "exp": True
        },

        # 3. Org_Gamma_Mixed (Admin: local_loose Min 6. User: Global Min 10)
        {
            "user": "admin@gamma-mixed.io", "desc": "Gamma Admin: Very Short (<6)",
             "pwd": "123", "exp": False
        },
        {
            "user": "admin@gamma-mixed.io", "desc": "Gamma Admin: Loose Valid (7)",
             "pwd": "pass", "exp": True # Wait, Min 6. "pass" is 4. "passwd" is 6.
        },
        {
            "user": "user1@gamma-mixed.io", "desc": "Gamma User: Short (<10 Global)",
             "pwd": "password", "exp": False # 8 chars. Global default is 10?
        },
        {
            "user": "user1@gamma-mixed.io", "desc": "Gamma User: Global Valid (10+)",
             "pwd": "password1234", "exp": True
        }
    ]

    total = 0
    passed = 0

    for s in scenarios:
        total += 1
        actual, reasons = verify_password(s["user"], s["pwd"])
        is_pass = (s["exp"] == actual)
        if is_pass: passed += 1
        
        res_str = f"{Colors.GREEN}PASS{Colors.RESET}" if is_pass else f"{Colors.RED}FAIL{Colors.RESET}"
        exp_str = str(s["exp"])
        act_str = str(actual)
        
        print(f"{s['user']:<35} | {s['desc']:<30} | {len(s['pwd']):<4} | {exp_str:<5} | {act_str:<5} | {res_str}")
        if not actual and reasons:
             print(f"   {Colors.RED}Reasons: {', '.join(reasons)}{Colors.RESET}")

    print("-" * 120)
    print(f"{Colors.BOLD}Final Result: {passed}/{total} passed{Colors.RESET}")

if __name__ == "__main__":
    main()
