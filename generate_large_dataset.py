
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
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR)
    
    # 2. Load Global Roles (SagaID)
    if os.path.exists(SAGAID_DATA_PATH):
        saga_data = load_json(SAGAID_DATA_PATH)
        global_roles = saga_data.get("global_roles", {})
        global_policies = saga_data.get("global_policies", {})
    else:
        print("Warning: SagaID data not found, using empty defaults.")
        global_roles = {}
        global_policies = {}

    # Write Global Data
    # Add a global definition for password/mfa defaults as well if missing
    if "password" not in global_policies:
         global_policies["password"] = {
             "default": {"password_min_length": 10}
         }
    # ADDED: MFA Definitions
    if "mfa" not in global_policies:
        global_policies["mfa"] = {
            "admins": {"mfa_required": True},
            "default": {"mfa_required": False},
            "all_users": {"mfa_required": True}
        }
    
    # Save as policy_data/global/data.json
    save_json(f"{OUTPUT_DIR}/global/data.json", {
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
            departments[d_name] = {"assigned_policies": {}}
            
        # Groups
        groups = {}
        for g_idx in range(GROUPS_PER_ORG):
            g_name = GROUP_NAMES[g_idx]
            # Round robin dept assignment
            dept = DEPT_NAMES[g_idx % len(DEPT_NAMES)]
            groups[g_name] = {
                "dept_id": dept,
                "assigned_policies": {}
            }
            
        # Org Structure
        org_data = {
            "organizations": {
                org_id: {
                    "defined_policies": {}, # Could replicate local policies if needed
                    "assigned_policies": {
                        "password": "default", # Referencing generic default
                        "access": "Global_Access_User",
                        "mfa": "admins"
                    },
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
            
            # Random Attributes
            # Pick a group
            grp = GROUP_NAMES[u_idx % len(GROUP_NAMES)]
            dept = groups[grp]["dept_id"]
            
            # Pick a role (e.g. billing_admin vs employee)
            # Make sure at least one user is admin
            if u_idx == 1:
                assigned_roles = ["msp_admin"] if "msp_admin" in role_keys else ["admin"]
            else:
                assigned_roles = [random.choice(role_keys)]
                
            org_data["users"][user_id] = {
                "org_id": org_id,
                "dept_id": dept,
                "groups": [grp],
                "roles": assigned_roles,
                "policy_overrides": {}
            }
            
        # Save as policy_data/organizations/{org_id}/data.json
        save_json(f"{OUTPUT_DIR}/organizations/{org_id}/data.json", org_data)

if __name__ == "__main__":
    generate_dataset()
