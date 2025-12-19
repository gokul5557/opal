
import pandas as pd
import json
import re

EXCEL_PATH = "/home/gokul/oidc+apisix/python/opal_testing/sagaid_roles.xlsx"
OUTPUT_PATH = "sagaid_data.json"

# Permission Mappings
PERM_MAP = {
    "Edit": ["read", "write"],
    "Read Only": ["read"],
    "No Access": []
}

def clean_scope_name(raw_text):
    """
    Extracts a clean scope name from the verbose Excel description.
    Example: '\nBilling\n1. View Invoice...' -> 'Billing'
    """
    if not isinstance(raw_text, str):
        return "Unknown"
    
    # Take the first non-empty line
    lines = [l.strip() for l in raw_text.split('\n') if l.strip()]
    if lines:
        # Remove numbers like '1. ' if present? No, usually the title is the first line.
        title = lines[0]
        # Basic normalization: 'Billing ' -> 'billing'
        return title.lower().replace(" ", "_").replace("/", "_")
    return "unknown"

def generate_policies():
    print(f"Reading {EXCEL_PATH}...")
    # Read with header=1 because Row 0 seems to be a super-header ('Roles')
    df = pd.read_excel(EXCEL_PATH, header=1) 
    
    print(f"Columns found: {df.columns.tolist()}")
    
    # Identify Role Columns (Skip 'Scopes')
    role_columns = [c for c in df.columns if c != 'Scopes' and "Unnamed" not in str(c)]
    
    print(f"Found Roles: {role_columns}")
    
    generated_roles = {}
    
    # Initialize roles
    for role in role_columns:
        role_key = role.lower().replace(" ", "_")
        generated_roles[role_key] = {
            "assigned_policies": {
                "access": f"access_role_{role_key}" 
            },
            "inherited_roles": []
        }

    generated_policies = {}

    # Iterate Roles to build their Access Policy
    for role in role_columns:
        role_key = role.lower().replace(" ", "_")
        policy_key = f"access_role_{role_key}"
        
        prefixes = []
        
        # Iterate Rows (Scopes)
        for index, row in df.iterrows():
            scope_raw = row['Scopes']
            permission_raw = row[role] # e.g. "Edit", "No Access"
            
            # Skip if permission is NaN or No Access
            if pd.isna(permission_raw) or permission_raw == "No Access":
                continue
                
            scope_name = clean_scope_name(scope_raw)
            perms = PERM_MAP.get(permission_raw, [])
            
            # Construct meaningful prefixes
            # e.g. /api/billing
            if scope_name != "unknown":
                prefixes.append(f"/api/{scope_name}")
        
        # Determine global permissions (if any 'Edit' exists, give 'write'?)
        # For simplicity, we list the prefixes. The 'permissions' block in OPA access policy
        # is usually global for that policy.
        # If a role has MIXED (Read some, Write others), we might need granularity.
        # But for this POC, let's assume if they have ANY edit, they get write perm.
        
        # Check if ANY row was 'Edit'
        has_write = any(row[role] == "Edit" for index, row in df.iterrows())
        
        policy_perms = ["read"]
        if has_write:
            policy_perms.append("write")
            
        generated_policies[policy_key] = {
            "prefixes": prefixes,
            "permissions": policy_perms
        }

    # Output Structure
    final_output = {
        "global_roles": generated_roles,
        "global_policies": {
            "access": generated_policies
        }
    }
    
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(final_output, f, indent=2)
    
    print(f"Generated {OUTPUT_PATH}")

if __name__ == "__main__":
    generate_policies()
