import json
import random
import os

def generate_password_policy(strictness):
    if strictness == "high":
        return {
            "password_min_length": 12,
            "password_require_number": True,
            "password_require_special_char": True,
            "password_require_uppercase": True,
            "password_require_lowercase": True,
            "password_reject_common": True,
            "password_reject_user_info": True
        }
    elif strictness == "medium":
        return {
            "password_min_length": 10,
            "password_require_number": True,
            "password_require_special_char": False,
            "password_reject_common": True
        }
    else: # low
        return {
            "password_min_length": 8,
            "password_require_number": False,
            "password_require_special_char": False,
             "password_reject_common": False
        }

def generate_mfa_policy(strictness):
    if strictness == "high":
        return {"mfa_required": True}
    return {"mfa_required": False}

def generate_session_policy(strictness):
    if strictness == "high":
        return {"session_timeout_minutes": 15, "max_sessions": 1}
    elif strictness == "medium":
        return {"session_timeout_minutes": 60, "max_sessions": 5}
    return {"session_timeout_minutes": 1440, "max_sessions": 10}

def generate_ip_policy(org_id):
    # Just generic
    return {"allowed_cidrs": [f"10.{random.randint(0,255)}.0.0/16"]}

def main():
    data = {
        "organizations": {},
        "users": {},
        "common_passwords": ["password", "123456", "admin"]
    }

    num_orgs = 5
    depts_per_org = 4
    groups_per_dept = 5
    users_per_group_min = 3
    users_per_group_max = 5

    org_names = [f"Org_{i+1}" for i in range(num_orgs)]
    deps_pool = ["Engineering", "Sales", "HR", "Finance"]
    
    for org_id in org_names:
        print(f"Generating Modular Org: {org_id}...")
        
        # 1. Defined Policies (Typed Buckets)
        defined_policies = {
            "password": {},
            "mfa": {},
            "session": {},
            "ip_whitelist": {},
            "access": {}
        }
        
        # Create standard variants for each type
        # Password
        defined_policies["password"][f"{org_id}_Pwd_High"] = generate_password_policy("high")
        defined_policies["password"][f"{org_id}_Pwd_Med"] = generate_password_policy("medium")
        defined_policies["password"][f"{org_id}_Pwd_Low"] = generate_password_policy("low")
        
        # MFA
        defined_policies["mfa"][f"{org_id}_MFA_Enforced"] = generate_mfa_policy("high")
        defined_policies["mfa"][f"{org_id}_MFA_Optional"] = generate_mfa_policy("low")
        
        # Session
        defined_policies["session"][f"{org_id}_Sess_Strict"] = generate_session_policy("high")
        defined_policies["session"][f"{org_id}_Sess_Std"] = generate_session_policy("low")
        
        # IP 
        defined_policies["ip_whitelist"][f"{org_id}_IP_Office"] = generate_ip_policy(org_id)
        defined_policies["ip_whitelist"][f"{org_id}_IP_Any"] = {"allowed_cidrs": ["0.0.0.0/0"]}
        
        # Access (Prefixes)
        defined_policies["access"][f"{org_id}_Access_Admin"] = {"allowed_prefixes": ["/admin", "/api"]}
        defined_policies["access"][f"{org_id}_Access_User"] = {"allowed_prefixes": ["/app", "/home"]}
        
        # 2. Assign Default Policies to Org
        org_assignments = {
            "password": f"{org_id}_Pwd_Med",
            "mfa": f"{org_id}_MFA_Optional",
            "session": f"{org_id}_Sess_Std",
            "ip_whitelist": f"{org_id}_IP_Any",
            "access": f"{org_id}_Access_User"
        }

        # 3. Departments
        org_deps = random.sample(deps_pool, k=depts_per_org) # Ensure unique if possible or just use pool
        departments = {}
        
        for d in org_deps:
            # Randomly override some assignments
            d_assignments = {}
            if d == "Engineering":
                 d_assignments["password"] = f"{org_id}_Pwd_High" # Engineers need strong pwd
            if d == "Finance":
                 d_assignments["mfa"] = f"{org_id}_MFA_Enforced" # Finance needs MFA
            
            departments[d] = {"assigned_policies": d_assignments}

        # 4. Groups
        org_groups = {}
        list_of_group_names = []
        for g_idx in range(depts_per_org * groups_per_dept):
             g_name = f"{org_id}_Group_{g_idx+1}"
             list_of_group_names.append(g_name)
             
             # Assign to a department (distribute evenly)
             dept_assigned = org_deps[g_idx % len(org_deps)]
             
             org_groups[g_name] = {
                 "assigned_policies": {},
                 "dept_id": dept_assigned
             }

        data["organizations"][org_id] = {
            "defined_policies": defined_policies,
            "assigned_policies": org_assignments,
            "departments": departments,
            "groups": org_groups
        }
        
        # 5. Users
        org_users = {}
        for g_name in list_of_group_names:
            # Resolve the group's department
            group_dept = org_groups[g_name]["dept_id"]
            
            count = random.randint(users_per_group_min, users_per_group_max)
            for _ in range(count):
                if org_users and random.random() < 0.3:
                    u_id = random.choice(list(org_users.keys()))
                    if g_name not in org_users[u_id]["groups"]:
                        org_users[u_id]["groups"].append(g_name)
                else:
                    u_suffix = random.randint(1000, 99999)
                    u_id = f"user_{u_suffix}@{org_id}.com".lower()
                    # User's primary dept should probably match their primary group's dept
                    org_users[u_id] = {
                        "org_id": org_id,
                        "dept_id": group_dept, 
                        "groups": [g_name],
                        "policy_overrides": {}
                    }
        data["users"].update(org_users)

    # ---------------------------------------------------------
    # TEST FIXTURES (Acme Corp)
    # ---------------------------------------------------------
    print("Injecting Modular Test Fixtures (Acme Corp)...")
    
    acme_policies = {
        "password": {
            "acme_pwd_default": { "password_min_length": 8, "password_require_number": True, "password_reject_common": True },
            "acme_pwd_strict": { "password_min_length": 12, "password_require_special_char": True, "password_reject_common": True },
            "acme_pwd_short": { "password_min_length": 5 } # For testing fail
        },
        "mfa": {
            "acme_mfa_none": { "mfa_required": False },
            "acme_mfa_required": { "mfa_required": True }
        },
        "ip_whitelist": {
            "acme_ip_int": { "allowed_cidrs": ["10.0.0.0/8"] },
            "acme_ip_any": { "allowed_cidrs": ["0.0.0.0/0"] }
        },
        "access": {
            "acme_public": { "allowed_prefixes": ["/public", "/auth"] },
            "acme_secure": { "allowed_prefixes": ["/git", "/jenkins"] }
        },
        "session": {
            "acme_sess_day": { "session_timeout_minutes": 1440 },
            "acme_sess_short": { "session_timeout_minutes": 240 }
        }
    }
    
    data["organizations"]["acme_corp"] = {
        "defined_policies": acme_policies,
        "assigned_policies": {
            "password": "acme_pwd_default",
            "mfa": "acme_mfa_none",
            "ip_whitelist": "acme_ip_int",
            "access": "acme_public",
            "session": "acme_sess_day"
        },
        "departments": {
            "engineering": {
                "assigned_policies": {
                    "password": "acme_pwd_strict",
                    "mfa": "acme_mfa_required",
                    "access": "acme_secure"
                }
            },
            "sales": {
                 "assigned_policies": {
                     "session": "acme_sess_short"
                 }
            }
        },
        "groups": {
            "remote_workers": {
                "assigned_policies": {
                    "ip_whitelist": "acme_ip_any"
                },
                "dept_id": "engineering"
            }
        }
    }
    
    # Startup Inc
    data["organizations"]["start_up_inc"] = {
         "defined_policies": {
             "mfa": { "startup_mfa": {"mfa_required": True} },
             "password": { "startup_pwd": {"password_min_length": 10}}
         },
         "assigned_policies": {
             "mfa": "startup_mfa",
             "password": "startup_pwd"
         },
         "departments": {},
         "groups": {}
    }

    test_users = {
        "alice@acme.com": { "org_id": "acme_corp", "dept_id": "engineering", "groups": [] },
        "bob@acme.com": { "org_id": "acme_corp", "dept_id": "engineering", "groups": ["remote_workers"] },
        "charlie@acme.com": { "org_id": "acme_corp", "dept_id": "sales", "groups": [] },
        "dave@startup.com": { "org_id": "start_up_inc", "dept_id": None, "groups": [] }
    }
    data["users"].update(test_users)
    
    with open("data.json", "w") as f:
        json.dump(data, f, indent=2)
    print("Modular data.json created!")

if __name__ == "__main__":
    main()
