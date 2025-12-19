
import requests
import json
import sys

# OPAL Client OPA Data Port (Default 8181 for OPA direct access, sometimes 7000 via OPAL)
# Docker Compose maps 8181:8181 for OPA.
OPA_URL = "http://localhost:8181/v1/data"

def verify_simulation():
    print(f"Connecting to OPA at {OPA_URL}...")
    
    try:
        # Query virtual 'users' from inheritance policy
        response = requests.post(f"{OPA_URL}", json={
            "input": {}, 
            "query": "data.policies.common.inheritance.users"
        })
        
        if response.status_code != 200:
            print(f"[FAIL] Connection Error: {response.status_code} {response.text}")
            return
            
        result = response.json()
        # OPA query result structure: {"result": [{"expressions": [{"value": {...}}]}]}
        # Direct data query vs query param?
        # If accessing /v1/data/policies/common/inheritance/users, it returns object key-value
        
        response_direct = requests.get(f"{OPA_URL}/policies/common/inheritance/users")
        if response_direct.status_code == 200:
             users_map = response_direct.json().get("result", {})
        else: 
             print("[FAIL] Could not fetch virtual users.")
             users_map = {}
        
        user_count = len(users_map)
        print(f"Users Found: {user_count}")
        
        if user_count == 30:
            print("[PASS] Successfully loaded 30 users.")
        else:
            print(f"[FAIL] Expected 30 users, found {user_count}.")
            
        # Check Specific User Role
        user_key = "user_1@org_1.com"
        if user_key in users_map:
            u1 = users_map[user_key]
            print(f"User {user_key} Roles: {u1.get('roles')}")
            # Verify Roles (SagaID)
            # Generator assigns 'msp_admin' or 'admin' to user_1
            if "msp_admin" in u1.get("roles", []) or "admin" in u1.get("roles", []):
                 print("[PASS] User 1 has correct Admin role.")
            else:
                 print(f"[FAIL] User 1 missing generated role. Found: {u1.get('roles')}")
                 
    except Exception as e:
        print(f"[FAIL] Execution Error: {e}")

if __name__ == "__main__":
    verify_simulation()
