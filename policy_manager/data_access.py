import json
import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "../data.json")

def load_data():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

def get_organizations():
    data = load_data()
    return data.get("organizations", {})

def get_org(org_id):
    orgs = get_organizations()
    return orgs.get(org_id)

def rename_org(old_id, new_id):
    data = load_data()
    orgs = data.get("organizations", {})
    
    # Validation
    if old_id not in orgs:
        return False, "Old Org ID not found"
    if new_id in orgs:
        return False, "New Org ID already exists"
    
    # 1. Rename Key in Organizations
    orgs[new_id] = orgs.pop(old_id)
    
    # 2. Update all Users belonging to this Org
    users = data.get("users", {})
    count = 0
    for uid, user in users.items():
        if user.get("org_id") == old_id:
            user["org_id"] = new_id
            count += 1
            
    save_data(data)
    return True, f"Renamed {old_id} to {new_id}. Updated {count} users."
