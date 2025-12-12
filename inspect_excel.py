
import pandas as pd
import json

file_path = "/home/gokul/oidc+apisix/python/opal_testing/Combined_API_List.xlsx"

try:
    xls = pd.ExcelFile(file_path)
    print("Sheet Names:", xls.sheet_names)
    
    df = pd.read_excel(file_path)
    # Print raw columns
    print("Raw Columns:", [repr(c) for c in df.columns])
    
    df.columns = df.columns.str.strip()
    
    # Heuristic Role Mapping
    # format: RoleName -> [Keywords in URI]
    role_map = {
        "super_admin": ["msp", "frappe.auth", "frappe.client", "system"], # MSP/System level
        "billing_admin": ["billing", "invoice", "payment", "wallet", "subscription"],
        "org_admin": ["organization", "domain", "dns", "org_admin"],
        "user_admin": ["directory.account", "directory.signup", "directory.login", "user_login"],
        "department_admin": ["department", "designation", "work_location"],
        "group_admin": ["group"],
        "employee_apps": ["/mail/", "/drive/", "/calendar/", "/meet/", "/chat/"]
    }
    
    deduced_roles = {r: [] for r in role_map.keys()}
    deduced_roles["general_api"] = [] # Fallback
    
    if 'uri' in df.columns:
        print("Classifying APIs into Roles...")
        for uri in df['uri'].dropna().unique():
            assigned = False
            uri_lower = uri.lower()
            
            for role, keywords in role_map.items():
                if any(k in uri_lower for k in keywords):
                    deduced_roles[role].append(uri)
                    assigned = True
                    # Don't break, an API might be relevant to multiple admins? 
                    # For now, let's allow multi-assignment or priority. 
                    # Let's break to assign to the *first* match (priority order)
                    break 
            
            if not assigned:
                deduced_roles["general_api"].append(uri)
                
        # Save results
        import json
        with open("deduced_roles.json", "w") as f:
            json.dump(deduced_roles, f, indent=2)
            
        print("JSON_START")
        print(json.dumps(deduced_roles, indent=2))
        print("JSON_END")
        print(f"Saved to deduced_roles.json. Uncategorized: {len(deduced_roles['general_api'])}")
    else:
        print("URI column missing.")
    
except Exception as e:
    print(f"Error reading excel: {e}")
