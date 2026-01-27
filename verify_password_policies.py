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
    print(f"{Colors.BOLD}Starting Password Policy Verification...{Colors.RESET}")
    print("-" * 100)
    print(f"{'User (Role)':<30} | {'Password Scenario':<30} | {'Len':<4} | {'Exp':<5} | {'Act':<5} | {'Result'}")
    print("-" * 100)

    # Scenarios
    # Admin: Strict (Min 16 + Special)
    # User: Simple (Min 8)

    scenarios = [
        # USER: Alice (Simple: Min 8)
        {
            "user": "alice@companyabc.com", "role": "User (Simple)",
            "pwd": "short", "desc": "Too Short (<8)", "exp": False
        },
        {
            "user": "alice@companyabc.com", "role": "User (Simple)",
            "pwd": "password123", "desc": "Valid Length (11)", "exp": True
        },
        
        # ADMIN: Admin (Strict: Min 16 + Special)
        {
            "user": "admin@companyabc.com", "role": "Admin (Strict)",
            "pwd": "password123", "desc": "Too Short (11)", "exp": False
        },
        {
            "user": "admin@companyabc.com", "role": "Admin (Strict)",
            "pwd": "longpasswordbutnospecial", "desc": "Long No Special (24)", "exp": False
        },
        {
            "user": "admin@companyabc.com", "role": "Admin (Strict)",
            "pwd": "longpasswordwithspecial!", "desc": "Valid (24 + Special)", "exp": True
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
        
        print(f"{s['role']:<30} | {s['desc']:<30} | {len(s['pwd']):<4} | {exp_str:<5} | {act_str:<5} | {res_str}")
        if not actual and reasons:
             print(f"   {Colors.RED}Reasons: {', '.join(reasons)}{Colors.RESET}")


    print("-" * 100)
    print(f"{Colors.BOLD}Final Result: {passed}/{total} passed{Colors.RESET}")

if __name__ == "__main__":
    main()
