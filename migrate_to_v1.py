import os
import json
import glob

ORGS_DIR = "policy_data/organizations"

def migrate_to_free_tier():
    org_files = glob.glob(os.path.join(ORGS_DIR, "*", "data.json"))
    print(f"Found {len(org_files)} organizations to migrate.")
    
    for org_file in org_files:
        try:
            with open(org_file, 'r') as f:
                data = json.load(f)
            
            # Switch plan to free_tier
            old_plan = data.get("plan", "unknown")
            data["plan"] = "free_tier"
            
            # Ensure no password/mfa policies are explicitly assigned at org level (if we want to purely rely on access)
            # The prompt says: "keep the plan but add the new free tieer plan ... no need to remove plans liek password and mfa"
            # But earlier said "in v1 oly two things apisix and acesss no pasword polcy and mfa"
            # It seems safer to just switch the plan. The global 'free_tier' only has 'access' assigned.
            # If the org has overrides in "assigned_policies", they might persist.
            # Let's trust the inheritance: Plan = free_tier -> access=global_user_access.
            
            with open(org_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            print(f"Migrated {org_file} (Plan: {old_plan} -> free_tier)")
            
        except Exception as e:
            print(f"Error migrating {org_file}: {e}")

if __name__ == "__main__":
    migrate_to_free_tier()
