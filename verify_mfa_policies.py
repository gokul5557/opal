import json
import requests
from typing import Dict, List, Any

# Configuration
OPA_URL = "http://localhost:8181/v1/data/mail_service/mfa/requirements"

# ANSI Colors
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def verify_mfa(user_id: str) -> Any:
    payload = {
        "input": {
            "user_id": user_id
        }
    }
    try:
        resp = requests.post(OPA_URL, json=payload)
        return resp.json().get("result", "UNKNOWN")
    except Exception as e:
        print(f"Error: {e}")
        return "ERROR"

def main():
    print(f"{Colors.BOLD}Starting MFA Policy Verification...{Colors.RESET}")
    print("-" * 100)
    print(f"{'User':<30} | {'Role':<15} | {'Exp':<15} | {'Act':<15} | {'Result'}")
    print("-" * 100)

    scenarios = [
        # USER: Alice (Simple: No MFA)
        {
            "user": "alice@companyabc.com", "role": "User",
            "exp": None
        },
        
        # ADMIN: Admin (Strict: TOTP)
        {
            "user": "admin@companyabc.com", "role": "Admin",
            "exp": ["totp"]
        }
    ]

    total = 0
    passed = 0

    for s in scenarios:
        total += 1
        actual = verify_mfa(s["user"])
        
        # Determine Pass/Fail
        # Note: None from Python matches null from JSON
        is_pass = (s["exp"] == actual)
        if is_pass: passed += 1
        
        res_str = f"{Colors.GREEN}PASS{Colors.RESET}" if is_pass else f"{Colors.RED}FAIL{Colors.RESET}"
        exp_str = str(s["exp"])
        act_str = str(actual)
        
        print(f"{s['user']:<30} | {s['role']:<15} | {exp_str:<15} | {act_str:<15} | {res_str}")

    print("-" * 100)
    print(f"{Colors.BOLD}Final Result: {passed}/{total} passed{Colors.RESET}")

if __name__ == "__main__":
    main()
