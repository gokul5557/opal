import json
import os
import glob
import sqlite3
from models import get_db_connection, DB_PATH

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_DATA_DIR = os.path.join(BASE_DIR, "../policy_data")
GLOBAL_DATA_PATH = os.path.join(POLICY_DATA_DIR, "global/data.json")
ORGS_DIR = os.path.join(POLICY_DATA_DIR, "organizations")

def import_from_json():
    """Reads JSON files and populates SQLite."""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Clear existing
    c.execute("DELETE FROM global_policy")
    c.execute("DELETE FROM global_role")
    c.execute("DELETE FROM user")
    c.execute("DELETE FROM organization")
    
    # 2. Import Global Data
    if os.path.exists(GLOBAL_DATA_PATH):
        with open(GLOBAL_DATA_PATH, 'r') as f:
            data = json.load(f)
            
            # Global Policies
            gp = data.get("global_policies", {})
            for cat, policies in gp.items():
                for name, definition in policies.items():
                    c.execute("INSERT INTO global_policy (category, name, definition_json) VALUES (?, ?, ?)",
                              (cat, name, json.dumps(definition)))
            
            # Global Roles
            gr = data.get("global_roles", {})
            for name, config in gr.items():
                c.execute("INSERT INTO global_role (role_name, assigned_policies_json) VALUES (?, ?)",
                          (name, json.dumps(config.get("assigned_policies", {}))))

    # 3. Import Organizations
    org_files = glob.glob(os.path.join(ORGS_DIR, "*/data.json"))
    for org_file in org_files:
        with open(org_file, 'r') as f:
            data = json.load(f)
            org_id = os.path.basename(os.path.dirname(org_file))
            
            # Org Entry
            org_config = {k: v for k, v in data.items() if k not in ["users"]}
            c.execute("INSERT INTO organization (org_id, name, config_json) VALUES (?, ?, ?)",
                      (org_id, org_id, json.dumps(org_config)))
            
            # Users
            users = data.get("users", {})
            for email, uinfo in users.items():
                c.execute("INSERT INTO user (email, org_id, roles, status, meta_json) VALUES (?, ?, ?, ?, ?)",
                          (email, org_id, ",".join(uinfo.get("roles", [])), uinfo.get("status", "active"), 
                           json.dumps({k: v for k, v in uinfo.items() if k not in ["roles", "status"]})))
    
    conn.commit()
    conn.close()
    return True

def export_to_json():
    """Writes SQLite data back to JSON files."""
    conn = get_db_connection()
    c = conn.cursor()
    
    # 1. Export Global Data
    global_data = {
        "global_policies": {},
        "global_roles": {}
    }
    
    c.execute("SELECT * FROM global_policy")
    for row in c.fetchall():
        cat = row['category']
        if cat not in global_data["global_policies"]:
            global_data["global_policies"][cat] = {}
        global_data["global_policies"][cat][row['name']] = json.loads(row['definition_json'])
        
    c.execute("SELECT * FROM global_role")
    for row in c.fetchall():
        global_data["global_roles"][row['role_name']] = {
            "assigned_policies": json.loads(row['assigned_policies_json'])
        }
        
    os.makedirs(os.path.dirname(GLOBAL_DATA_PATH), exist_ok=True)
    with open(GLOBAL_DATA_PATH, 'w') as f:
        json.dump(global_data, f, indent=2)

    # 2. Export Organizations
    c.execute("SELECT * FROM organization")
    org_rows = c.fetchall()
    for org in org_rows:
        org_id = org['org_id']
        org_data = json.loads(org['config_json'])
        org_data["users"] = {}
        
        c.execute("SELECT * FROM user WHERE org_id=?", (org_id,))
        user_rows = c.fetchall()
        for u in user_rows:
            u_meta = json.loads(u['meta_json'])
            u_meta["roles"] = u['roles'].split(",") if u['roles'] else []
            u_meta["status"] = u['status']
            org_data["users"][u['email']] = u_meta
            
        org_path = os.path.join(ORGS_DIR, org_id, "data.json")
        os.makedirs(os.path.dirname(org_path), exist_ok=True)
        with open(org_path, 'w') as f:
            json.dump(org_data, f, indent=2)
            
    conn.close()
    return True
