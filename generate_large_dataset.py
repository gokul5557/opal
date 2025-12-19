
import json
import os
import shutil
import random

SAGAID_DATA_PATH = "sagaid_data.json"
OUTPUT_DIR = "policy_data"

ORGS_COUNT = 10
DEPTS_PER_ORG = 3
GROUPS_PER_ORG = 5
USERS_PER_ORG = 10

DEPT_NAMES = ["Engineering", "Sales", "HR"]
GROUP_NAMES = ["Team_Alpha", "Team_Beta", "Team_Gamma", "Team_Delta", "Team_Epsilon"]

def load_json(path):
    with open(path, 'r') as f:
        return json.load(f)

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Created {path}")

def generate_dataset():
    # 1. Setup Directory
    # Ensure we don't delete global data if we need it
    GLOBAL_DATA_FILE = f"{OUTPUT_DIR}/global/data.json"
    global_roles = {}
    global_policies = {}
    
    if os.path.exists(GLOBAL_DATA_FILE):
        print(f"Loading existing Real Data from {GLOBAL_DATA_FILE}")
        existing_global = load_json(GLOBAL_DATA_FILE)
        global_roles = existing_global.get("global_roles", {})
        global_policies = existing_global.get("global_policies", {})
    elif os.path.exists(SAGAID_DATA_PATH):
        # Fallback to sagaid_data
        saga_data = load_json(SAGAID_DATA_PATH)
        global_roles = saga_data.get("global_roles", {})
        global_policies = saga_data.get("global_policies", {})

    # Ensure defaults exist
    if "password" not in global_policies:
         global_policies["password"] = {
             "default": {"password_min_length": 10}
         }
    if "mfa" not in global_policies:
        global_policies["mfa"] = {
            "admins": {"mfa_required": True},
            "default": {"mfa_required": False},
            "all_users": {"mfa_required": True}
        }

    # Assign MFA to Admin Roles (In-Memory update of loaded/empty roles)
    admin_roles = ["msp_admin", "org_admin", "admin", "security_admin"]
    for r in admin_roles:
        if r not in global_roles: continue
        if "assigned_policies" not in global_roles[r]:
            global_roles[r]["assigned_policies"] = {}
        global_roles[r]["assigned_policies"]["mfa"] = "admins"

    # Re-create output dir but preserve global if needed? 
    # Actually, safest is to write to a temp dict, clear dir, then write back.
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(f"{OUTPUT_DIR}/global")
    os.makedirs(f"{OUTPUT_DIR}/organizations")

    # Save Global Data (Real Data)
    # Save as policy_data/global/data.json
    save_json(GLOBAL_DATA_FILE, {
        "global_roles": global_roles,
        "global_policies": global_policies
    })
    
    role_keys = list(global_roles.keys()) if global_roles else ["employee"]
    
    # 3. Generate Orgs
    for i in range(1, ORGS_COUNT + 1):
        org_id = f"Org_{i}"
        
        # Departments
        departments = {}
        for d_name in DEPT_NAMES:
            departments[d_name] = {
                "assigned_policies": {} 
            }
            
        # Groups
        groups = {}
        for g_idx in range(GROUPS_PER_ORG):
            g_name = GROUP_NAMES[g_idx]
            dept = DEPT_NAMES[g_idx % len(DEPT_NAMES)]
            groups[g_name] = {
                "dept_id": dept,
                "assigned_policies": {}
            }
        
        # VARIATION: Org_1 defines custom policy
        org_defined_policies = {}
        org_assigned_policies = {
             "password": "default",
             "access": "Global_Access_User", # Placeholder if using roles primarily
             "mfa": "default" # Default False, let Roles override
        }

        if i == 1:
            # Org 1: Strict Password
            org_defined_policies["password"] = {
                "strict": {"password_min_length": 20}
            }
            org_assigned_policies["password"] = "strict" # Override Global Default
            
            # Org 1: Engineering Dept gets stricter MFA?
            departments["Engineering"]["assigned_policies"]["mfa"] = "admins" # effectively force true? 
            # (Note: policy logic unions requirements. If global=default(false) and dept=admins(true), union might depend on policy code)

        # Org Structure
        org_data = {
            "organizations": {
                org_id: {
                    "defined_policies": org_defined_policies, 
                    "assigned_policies": org_assigned_policies,
                    "departments": departments,
                    "groups": groups,
                    "roles": {} 
                }
            },
            "users": {}
        }
        
        # 4. Generate Users
        for u_idx in range(1, USERS_PER_ORG + 1):
            user_id = f"user_{u_idx}@{org_id.lower()}.com"
            grp = GROUP_NAMES[u_idx % len(GROUP_NAMES)]
            dept = groups[grp]["dept_id"]
            
            if u_idx == 1:
                assigned_roles = ["msp_admin"] if "msp_admin" in role_keys else ["admin"]
            else:
                assigned_roles = ["employee"]
                
            org_data["users"][user_id] = {
                "org_id": org_id,
                "dept_id": dept,
                "groups": [grp],
                "roles": assigned_roles,
                "policy_overrides": {}
            }
            
        save_json(f"{OUTPUT_DIR}/organizations/{org_id}/data.json", org_data)

if __name__ == "__main__":
    generate_dataset()
