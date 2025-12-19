
import json
import os
import shutil

SOURCE_DATA = "data.json"
OUTPUT_DIR = "policy_data"

def load_json(path):
    with open(path, 'r') as f:
        return json.load(f)

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Created {path}")

def split_data():
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR)
    
    data = load_json(SOURCE_DATA)
    
    # 1. Global Data
    global_data = {
        "global_policies": data.get("global_policies", {}),
        "global_roles": data.get("global_roles", {})
    }
    save_json(f"{OUTPUT_DIR}/global.json", global_data)
    
    # 2. Organizations
    orgs = data.get("organizations", {})
    users = data.get("users", {})
    
    # Process existing orgs
    for org_id, org_data in orgs.items():
        # Find users belonging to this org
        org_users = {uid: udata for uid, udata in users.items() if udata.get("org_id") == org_id}
        
        org_file_data = {
            "organizations": {
                org_id: org_data
            },
            "users": org_users
        }
        save_json(f"{OUTPUT_DIR}/organizations/{org_id}.json", org_file_data)
        
    # 3. Create Dummy Orgs (User requested "up to three org")
    dummy_orgs = ["acme_corp", "cyberdyne"]
    
    for org_id in dummy_orgs:
        org_file_data = {
            "organizations": {
                org_id: {
                    "defined_policies": {},
                    "assigned_policies": {},
                    "departments": {
                        "IT": {"assigned_policies": {}}
                    },
                    "groups": {
                        "admins": {"dept_id": "IT", "assigned_policies": {}}
                    },
                    "roles": {}
                }
            },
            "users": {
                f"admin@{org_id}.com": {
                    "org_id": org_id,
                    "dept_id": "IT",
                    "groups": ["admins"],
                    "roles": ["admin"]
                }
            }
        }
        save_json(f"{OUTPUT_DIR}/organizations/{org_id}.json", org_file_data)

if __name__ == "__main__":
    split_data()
