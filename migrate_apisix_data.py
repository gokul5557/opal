import json
import os

# ==========================================
# 1. LEGACY CONFIGURATION (From opa_admin.py)
# ==========================================
SERVICES = {
    "mail": ["/mail"],
    "drive": ["/drive"],
    "calendar": ["/calendar"],
    "meet": ["/meet", "/rooms"],
    "chat": ["/chat"],
    "admin": ["/api/method/saga_directory", "/api/method/saga_auth"],
    "billing": ["/api/method/billing"],
    "org": ["/api/method/organization"],
    "all": ["/"] 
}

PLANS = {
    "basic": ["mail", "drive"],
    "pro": ["mail", "drive", "calendar"],
    "premium": ["mail", "drive", "calendar", "meet"],
    "enterprise": ["mail", "drive", "calendar", "meet", "chat"] # explicit, no 'all' to avoid global wildcard
}

ROLES = {
    "workspace_admin": {"services": ["all"], "permissions": ["read", "write"]},
    "billing_admin": {"services": ["billing"], "permissions": ["read", "write"]},
    "org_admin": {"services": ["org"], "permissions": ["read", "write"]},
    "user_admin": {"services": ["admin"], "permissions": ["read", "write"]},
    "email_admin": {"services": ["mail"], "permissions": ["read", "write"]},
    "drive_admin": {"services": ["drive"], "permissions": ["read", "write"]},
    "calendar_admin": {"services": ["calendar"], "permissions": ["read", "write"]},
    "meet_admin": {"services": ["meet"], "permissions": ["read", "write"]},
    "employee": {"services": [], "permissions": ["read", "write"]},
    "guest": {"services": [], "permissions": ["read"]}
}

USERS_LEGACY = {
    "gokul@sagasoft.io": {"plan": "basic", "roles": ["employee"]},
    "gokul@sagaid.com": {"plan": "enterprise", "roles": ["workspace_admin"]},
    "billing@sagasoft.xyz": {"plan": "basic", "roles": ["billing_admin"]},
    "guest@sagasoft.xyz": {"plan": "pro", "roles": ["guest"]}
}

# ==========================================
# 2. HELPER: Resolve Services to Prefixes
# ==========================================
def resolve_prefixes(service_list):
    prefixes = set()
    for svc in service_list:
        if svc in SERVICES:
            for p in SERVICES[svc]:
                prefixes.add(p)
    return list(prefixes)

# ==========================================
# 3. MIGRATION LOGIC
# ==========================================
def migrate():
    DATA_FILE = "data.json"
    
    if not os.path.exists(DATA_FILE):
        print(f"Error: {DATA_FILE} not found.")
        return

    with open(DATA_FILE, "r") as f:
        data = json.load(f)

    org_id = "Org_1" # Default Org
    if org_id not in data["organizations"]:
        data["organizations"][org_id] = {"defined_policies": {}, "groups": {}, "departments": {}}

    org = data["organizations"][org_id]
    
    # Ensure Access Policy container exists
    if "access" not in org["defined_policies"]:
        org["defined_policies"]["access"] = {}
        
    # Initialize Roles container
    if "roles" not in org:
        org["roles"] = {}

    print("--- Migrating Plans (As Groups) ---")
    for plan_name, services in PLANS.items():
        # 1. Create Policy
        policy_id = f"access_plan_{plan_name}"
        prefixes = resolve_prefixes(services)
        permissions = ["read", "write"]
        
        policy_config = {
            "prefixes": prefixes,
            "permissions": permissions
        }
        org["defined_policies"]["access"][policy_id] = policy_config
        # print(f"Created Policy: {policy_id}")
        
        # 2. Assigning to Org directly (done at end), so NO GROUP created here.

    # --- RESET ROLES for Clean Migration ---
    # We want to remove legacy "service-based" roles (e.g. mail_service_medium)
    # and only keep what we are about to explicitly create.
    org["roles"] = {}
    
    # Also reset the defined policies related to roles? 
    # Yes, otherwise we have orphaned policies like "access_role_mail_service_medium".
    # But we must preserve the Plan policies (access_plan_*) which we just created above.
    # So we can't wipe the dict entirely unless we move the Plan creation AFTER this wipe.
    
    # DECISION: Move this wipe block UP, before Plan creation.
    # Actually, let's just wipe defined_policies["access"] completely at the start 
    # of the `migrate()` function if we want a clean slate.
    
    # Remove legacy Role policies (access_role_*) to cleanup UI
    access_policies = org["defined_policies"]["access"]
    keys_to_delete = [k for k in access_policies.keys() if k.startswith("access_role_")]
    for k in keys_to_delete:
        del access_policies[k]
    print(f"--- Wiped {len(keys_to_delete)} Legacy Role Policies ---")
    
    print("--- Cleared Existing Roles for Clean Slate ---")

    print("\n--- Migrating Roles (As explicit Roles) ---")
    for role_name, config in ROLES.items():
        # 1. Create Policy
        policy_id = f"access_role_{role_name}"
        prefixes = resolve_prefixes(config["services"])
        permissions = config["permissions"]
        
        policy_config = {
            "prefixes": prefixes,
            "permissions": permissions
        }
        org["defined_policies"]["access"][policy_id] = policy_config
        
        # 2. Create Role Entity
        org["roles"][role_name] = {"assigned_policies": {"access": policy_id}}
        print(f"Created Role: {role_name} -> {policy_id}")

    # --- NEW: Import Roles from Deduced JSON ---
    EXCEL_ROLES_FILE = "deduced_roles.json"
    if os.path.exists(EXCEL_ROLES_FILE):
        print(f"\n--- Importing Deduced Roles from {EXCEL_ROLES_FILE} ---")
        with open(EXCEL_ROLES_FILE, "r") as f:
            excel_roles = json.load(f)
            
        for r_name, r_uris in excel_roles.items():
            # Optimize: Clean name (e.g. billing_admin matching existing pattern)
            clean_role_name = r_name.lower()
            
            policy_id = f"access_role_{clean_role_name}"
            # Dedupe prefixes
            prefixes = list(set(r_uris))
            
            policy_config = {
                "prefixes": prefixes,
                "permissions": ["read", "write"] # Default full access to these URIs
            }
            
            # Save Policy
            org["defined_policies"]["access"][policy_id] = policy_config
            
            # Save Role (Overwrite key if exists to prefer this deduced list)
            org["roles"][clean_role_name] = {"assigned_policies": {"access": policy_id}}
            print(f"Created/Updated Role: {clean_role_name} -> {len(prefixes)} prefixes")
            
    # 1. Migrate specific Legacy Users
    for email, config in USERS_LEGACY.items():
        if email not in data["users"]:
            data["users"][email] = {
                "org_id": org_id,
                "dept_id": "Engineering",
                "groups": [],
                "roles": [],
                "policy_overrides": {}
            }
        
        user = data["users"][email]
        user["groups"] = [] 
        user["roles"] = []
        
        # Add Roles (Explicit List)
        for r in config["roles"]:
            user["roles"].append(r)
            
        print(f"Updated Legacy User {email}: Roles={user['roles']}")

    # 2. Randomly Assign Roles to ALL OTHER Users (No Plan Groups)
    import random
    
    all_plan_names = list(PLANS.keys())
    # Merge legacy roles + new excel roles for random assignment
    all_role_names = list(org["roles"].keys()) 
    
    # 3. Assign Org Default Plan (Random)
    random_org_plan = random.choice(all_plan_names)
    org_policy_id = f"access_plan_{random_org_plan}"
    org["assigned_policies"]["access"] = org_policy_id
    print(f"\nASSIGNED ORG DEFAULT ACCESS POLICY: {org_policy_id}")

    # Gather available "Team Groups" (Generic ones)
    team_groups = [g for g in org["groups"].keys() if g.startswith(f"{org_id}_Group_")]
    
    # Filter Admin Roles (exclude employee/guest for random add-on)
    # We allow random assignment of Excel roles too
    admin_roles = [r for r in all_role_names if r not in ["employee", "guest"]]

    print("\n--- Assigning Mandatory 'Employee' Role & Team Groups ---")
    for email, user in data["users"].items():
        # Skip if already migrated (Legacy users)
        # Actually, let's update EVERYONE to ensure consistency
        # if email in USERS_LEGACY: continue
            
        # Only touch users in the main Org_1
        if user.get("org_id") != org_id:
            continue
            
        # 1. Groups: Assign 1 random Team Group (Collaboration)
        # We wipe old "Plan_" groups by overwriting
        if team_groups:
            user["groups"] = [random.choice(team_groups)]
        else:
            user["groups"] = []
            
        # 2. Roles: Mandatory 'employee' + Random Admin
        user["roles"] = ["employee"]
        
        # 20% chance to be an Admin of some sort
        if random.random() < 0.2:
            user["roles"].append(random.choice(admin_roles))
             
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print("\n✅ Migration Complete. Everyone is 'Employee' + Assigned to Team Groups.")

if __name__ == "__main__":
    migrate()
