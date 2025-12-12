from flask import Flask, render_template, request, redirect, url_for
from data_access import get_organizations, get_org, save_data, load_data

app = Flask(__name__)

@app.route("/")
def dashboard():
    orgs = get_organizations()
    return render_template("dashboard.html", orgs=orgs)

@app.route("/org/<org_id>")
def org_details(org_id):
    data = load_data()
    org = data["organizations"].get(org_id)
    if not org:
        return "Org not found", 404
    
    # Filter users for this org
    all_users = {uid: udata for uid, udata in data["users"].items() if udata.get("org_id") == org_id}
    all_groups = org.get("groups", {})
    
    # Pagination Logic
    ITEMS_PER_PAGE = 10
    
    # Groups Pagination
    page_groups = request.args.get("page_groups", 1, type=int)
    total_groups = len(all_groups)
    total_pages_groups = (total_groups + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE
    start_g = (page_groups - 1) * ITEMS_PER_PAGE
    end_g = start_g + ITEMS_PER_PAGE
    paged_groups = dict(list(all_groups.items())[start_g:end_g])
    
    # Users Pagination
    page_users = request.args.get("page_users", 1, type=int)
    total_users = len(all_users)
    total_pages_users = (total_users + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE
    start_u = (page_users - 1) * ITEMS_PER_PAGE
    end_u = start_u + ITEMS_PER_PAGE
    paged_users = dict(list(all_users.items())[start_u:end_u])
    
    pagination = {
        "groups": {
            "current": page_groups,
            "total_pages": total_pages_groups,
            "has_next": page_groups < total_pages_groups,
            "has_prev": page_groups > 1,
            "next_num": page_groups + 1,
            "prev_num": page_groups - 1
        },
         "users": {
            "current": page_users,
            "total_pages": total_pages_users,
            "has_next": page_users < total_pages_users,
            "has_prev": page_users > 1,
            "next_num": page_users + 1,
            "prev_num": page_users - 1
        }
    }
    
    # We pass the full org object but override groups with paged version for display if needed, 
    # but since template iterates org.groups, we might need to pass paged_groups separately 
    # and update template to use it.
    
    return render_template("org_details.html", 
                           org_id=org_id, 
                           org=org, 
                           users=paged_users, 
                           groups=paged_groups,
                           pagination=pagination)

@app.route("/org/<org_id>/department/add")
def add_department(org_id):
    name = request.args.get("name")
    if name:
        data = load_data()
        org = data["organizations"][org_id]
        if name not in org["departments"]:
            # Default to Org's assigned policy initially or empty? 
            # Or assume default assignment logic. Let's start with Org's default.
            default_pid = org.get("assigned_policy_id", "")
            org["departments"][name] = {"assigned_policy_id": default_pid}
            save_data(data)
    return redirect(url_for("org_details", org_id=org_id))

@app.route("/org/<org_id>/policies/new")
def new_policy(org_id):
    p_type = request.args.get("type", "password")
    return render_template("policy_form.html", org_id=org_id, policy_id=None, policy={}, policy_type=p_type)

@app.route("/org/<org_id>/policies/edit/<p_type>/<policy_id>")
def edit_policy(org_id, p_type, policy_id):
    org = get_org(org_id)
    # Look up in defined_policies[type]
    policy = org.get("defined_policies", {}).get(p_type, {}).get(policy_id, {})
    return render_template("policy_form.html", org_id=org_id, policy_id=policy_id, policy=policy, policy_type=p_type)

@app.route("/org/<org_id>/policies/save", methods=["POST"])
def save_policy(org_id):
    print(f"DEBUG: save_policy hit for {org_id}")
    org_id = org_id
    new_pid = request.form.get("new_policy_id")
    p_type = request.form.get("policy_type")
    print(f"DEBUG: pid={new_pid}, type={p_type}")
    
    # Construct Policy Object based on Type
    policy = {}
    
    try:
        if p_type == "password":
            val = request.form.get("password_min_length", 8)
            print(f"DEBUG: password_min_length raw={val}")
            
            policy = {
                "password_min_length": int(val),
                "password_require_number": "password_require_number" in request.form,
                "password_require_special_char": "password_require_special_char" in request.form,
                "password_reject_common": "password_reject_common" in request.form
            }
        elif p_type == "access":
            raw_prefixes = request.form.get("prefixes", "")
            prefixes = [p.strip() for p in raw_prefixes.split(",") if p.strip()]
            
            permissions = []
            if "perm_read" in request.form: permissions.append("read")
            if "perm_write" in request.form: permissions.append("write")
            
            policy = {
                "prefixes": prefixes,
                "permissions": permissions
            }
        elif p_type == "mfa":
            policy = {
                "mfa_required": request.form.get("mfa_required") == "true"
            }
        elif p_type == "ip_whitelist":
            policy = {
                "allow_cidrs": [x.strip() for x in request.form.get("allow_cidrs", "").split(",") if x.strip()]
            }
        elif p_type == "session":
            policy = {
                "session_timeout_minutes": int(request.form.get("session_timeout_minutes", 1440))
            }
        print(f"DEBUG: Constructed policy: {policy}")
            
        data = load_data()
        if org_id in data["organizations"]:
            print("DEBUG: Org found")
            # Ensure dict exists
            if "defined_policies" not in data["organizations"][org_id]:
                data["organizations"][org_id]["defined_policies"] = {}
                
            if p_type not in data["organizations"][org_id]["defined_policies"]:
                 data["organizations"][org_id]["defined_policies"][p_type] = {}
                 
            data["organizations"][org_id]["defined_policies"][p_type][new_pid] = policy
            save_data(data)
            print("DEBUG: Saved data")
            
    except Exception as e:
        print(f"DEBUG: ERROR in save_policy: {e}")
        import traceback
        traceback.print_exc()
        return f"Error: {e}", 500
        
    return redirect(url_for("org_details", org_id=org_id))

@app.route("/org/<org_id>/assign/<target_type>/<target_name>")
def assign_policy(org_id, target_type, target_name):
    # target_type: 'department' or 'group'
    org = get_org(org_id)
    if not org: return "Org not found", 404
    
    current_assignments = {}
    if target_type == "department":
        current_assignments = org["departments"].get(target_name, {}).get("assigned_policies", {})
    elif target_type == "group":
        current_assignments = org["groups"].get(target_name, {}).get("assigned_policies", {})
        
    defined_policies = org.get("defined_policies", {})
    
    return render_template("assign_policy.html", 
                           org_id=org_id, 
                           target_type=target_type, 
                           target_name=target_name, 
                           current_assignments=current_assignments, 
                           defined_policies=defined_policies)

@app.route("/org/<org_id>/assign/save", methods=["POST"])
def save_assignment(org_id):
    target_type = request.form.get("target_type")
    target_name = request.form.get("target_name")
    
    data = load_data()
    org = data["organizations"].get(org_id)
    
    if org:
        target_obj = None
        if target_type == "department" and target_name in org["departments"]:
            target_obj = org["departments"][target_name]
        elif target_type == "group" and target_name in org["groups"]:
            target_obj = org["groups"][target_name]
        elif target_type == "organization":
            target_obj = org
            
        if target_obj:
            if "assigned_policies" not in target_obj:
                target_obj["assigned_policies"] = {}
            
            # Save for each type
            for ptype in ['password', 'mfa', 'ip_whitelist', 'session', 'access']:
                pid = request.form.get(f"policy_{ptype}")
                if pid:
                    target_obj["assigned_policies"][ptype] = pid
                elif ptype in target_obj["assigned_policies"]:
                    # Remove it if unselected (Inherit)
                    del target_obj["assigned_policies"][ptype]
                    
            save_data(data)
        
    return redirect(url_for("org_details", org_id=org_id))

import subprocess
import json
import os
import tempfile

@app.route("/api/test/password", methods=["POST"])
def test_password():
    user_email = request.form.get("user")
    password = request.form.get("password")
    
    if not user_email or not password:
        return {"error": "Missing user or password"}, 400

    # Prepare Input
    input_data = {
        "user": user_email,
        "password": password
    }
    
    # We need to run OPA against the parent directory where data.json and policies/ are
    # Current CWD is dynamic. Let's assume absolute paths or rely on relative.
    # The app is likely run from .../policy_poc/policy_manager or .../policy_poc
    # Let's find the root 'policy_poc' dir based on this file's location
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Write input to temp file
    with tempfile.NamedTemporaryFile(mode='w+', suffix=".json", delete=False) as temp_input:
        json.dump(input_data, temp_input)
        temp_input_path = temp_input.name
        
    try:
        # Command: opa eval ...
        # We query a constructed object to get both Deny Reasons and the Trace
        query = '{ "reasons": data.policies.security.password.deny, "trace": data.policies.common.inheritance.explain_config("password") }'
        
        cmd = [
            "opa", "eval",
            "-d", "policies",
            "-d", "data.json",
            "-i", temp_input_path,
            query
        ]
        
        print(f"DEBUG: Running Password OPA: {cmd} in {base_dir}", flush=True)
        
        result = subprocess.run(
            cmd, 
            cwd=base_dir, 
            capture_output=True, 
            text=True
        )
        
        if result.returncode != 0:
            return {"error": f"OPA Error: {result.stderr}"}, 500
            
        # Parse Output
        opa_json = json.loads(result.stdout)
        
        reasons = []
        trace = {}
        
        if "result" in opa_json and opa_json["result"]:
             expressions = opa_json["result"][0].get("expressions", [])
             if expressions:
                 val = expressions[0].get("value", {})
                 
                 # 1. Parse Reasons
                 r_val = val.get("reasons", [])
                 if isinstance(r_val, dict):
                     reasons = list(r_val.keys())
                 elif isinstance(r_val, list):
                     reasons = r_val
                     
                 # 2. Parse Trace
                 trace = val.get("trace", {})
                 
        allowed = (len(reasons) == 0)
        
        return {
            "allowed": allowed,
            "reasons": reasons,
            "trace": trace
        }
        
    except Exception as e:
        return {"error": str(e)}, 500
        
    finally:
        if os.path.exists(temp_input_path):
            os.remove(temp_input_path)

@app.route("/api/test/access", methods=["POST"])
def test_access():
    user = request.form.get("user")
    path = request.form.get("path")
    method = request.form.get("method")
    ip = request.form.get("ip", "127.0.0.1") # Default to localhost
    
    # Legacy: Strict requirement for user
    if not user or not path or not method:
        return {"error": "Missing user, path, or method"}, 400
        
    # Construct input for OPA
    headers = {
        "x-real-ip": ip or "127.0.0.1"
    }

    print(f"DEBUG: OPA Headers: {headers}")
    
    opa_input = {
        "user": user, 
        "ip": ip,
        "request": {
            "path": path,
            "method": method,
            "headers": headers
        }
    }
    # Create temp file
    fd, temp_input_path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(opa_input, f)
            
        # OPA Eval
        print(f"DEBUG: Starting OPA Eval for {user}")
        
        # Query for allow decision, reasons, and explanation
        # Pass the extracted user_email to the trace function to ensure it works for JWT flows too
        query = '{ "allow": data.policies.apisix.policy.allow, "reasons": data.policies.apisix.policy.deny, "trace": data.policies.common.inheritance.explain_config_merged_with_user("access", data.policies.apisix.policy.user_email) }'
        
        # Determine base dir correctly
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # Use specific paths to avoid scanning irrelevant files or large logs
        cmd = [
            "opa", "eval",
            "-d", "policies",
            "-d", "data.json",
            "-i", temp_input_path,
            query
        ]
        
        print(f"DEBUG: Running command: {cmd} in {base_dir}")
        
        result = subprocess.run(
            cmd, 
            cwd=base_dir, 
            capture_output=True, 
            text=True,
            timeout=5 # Fail fast to avoid hanging
        )
        
        if result.returncode != 0:
            print(f"DEBUG: OPA Failed: {result.stderr}")
            return {"error": f"OPA Error: {result.stderr}"}, 500
            
        # print(f"DEBUG: OPA Output: {result.stdout[:100]}...")
        opa_json = json.loads(result.stdout)
        
        allowed = False
        reasons = []
        trace = {}
        
        if "result" in opa_json and opa_json["result"]:
             expressions = opa_json["result"][0].get("expressions", [])
             if expressions:
                 val = expressions[0].get("value", {})
                 allowed = val.get("allow", False)
                 reasons_map = val.get("reasons", {})
                 if isinstance(reasons_map, list):
                     reasons = reasons_map
                 else:
                     reasons = list(reasons_map.keys())
                 trace = val.get("trace", {})
                 
        return {
            "allowed": allowed,
            "reasons": reasons,
            "trace": trace
        }
        
    except Exception as e:
        print(f"DEBUG: Exception: {e}")
        return {"error": str(e)}, 500
    finally:
         if os.path.exists(temp_input_path):
            os.remove(temp_input_path)

# --- Phase 9: User & Group Management ---

@app.route("/org/<org_id>/groups/add", methods=["POST"])
def add_group(org_id):
    name = request.form.get("name")
    dept_id = request.form.get("dept_id")
    
    if not name:
        return "Group name required", 400
        
    data = load_data()
    org = data["organizations"].get(org_id)
    if not org:
        return "Org not found", 404
        
    if name not in org["groups"]:
        org["groups"][name] = {
            "dept_id": dept_id,
            "assigned_policies": {}
        }
        save_data(data)
        
    return redirect(url_for("org_details", org_id=org_id))

@app.route("/org/<org_id>/users/add", methods=["POST"])
def add_user(org_id):
    email = request.form.get("email")
    dept_id = request.form.get("dept_id")
    group_list = request.form.getlist("groups") # Multi-select
    
    if not email:
        return "Email required", 400
        
    data = load_data()
    
    # Check if user exists? For now, we overwrite or update
    if email not in data["users"]:
        data["users"][email] = {}
        
    data["users"][email].update({
        "org_id": org_id,
        "dept_id": dept_id,
        "groups": group_list,
        # Preserve overrides if edit, but this is 'add' route. 
        # If we share logic, we should probably keep overrides.
        "policy_overrides": data["users"][email].get("policy_overrides", {}) 
    })
    
    save_data(data)
    return redirect(url_for("org_details", org_id=org_id))

@app.route("/api/users/update", methods=["POST"])
def update_user():
    email = request.form.get("email")
    dept_id = request.form.get("dept_id")
    group_list = request.form.getlist("groups")
    role_list = request.form.getlist("roles") # Added this
    org_id = request.form.get("org_id") 
    
    if not email:
        return "Email required", 400
        
    data = load_data()
    if email in data["users"]:
        data["users"][email]["dept_id"] = dept_id
        data["users"][email]["groups"] = group_list
        data["users"][email]["roles"] = role_list # Save this
        save_data(data)
    
    return redirect(url_for("org_details", org_id=org_id))

@app.route("/org/<org_id>/roles/save", methods=["POST"])
def save_role(org_id):
    role_name = request.form.get("role_name")
    inherited_roles = request.form.getlist("inherited_roles") # List of role names
    
    # Granular Permissions: Passed as JSON string from frontend or dynamic form fields?
    # Dynamic form fields are easier to debug: path_0, read_0, write_0...
    # Let's assume frontend sends a JSON string `permissions_data` for simplicity.
    perms_json = request.form.get("permissions_data") # [{"path": "/api/x", "read": true, "write": false}]
    
    if not role_name:
        return "Role Name Required", 400
        
    data = load_data()
    org = data["organizations"].get(org_id)
    if not org:
        return "Org not found", 404
        
    # 1. Ensure Roles container exists
    if "roles" not in org:
        org["roles"] = {}
        
    # 2. Create/Update Role Entity
    # Auto-generate policy ID if new
    policy_id = f"access_role_{role_name.lower().replace(' ', '_')}"
    
    if role_name not in org["roles"]:
        org["roles"][role_name] = {}
        
    org["roles"][role_name]["assigned_policies"] = {"access": policy_id}
    org["roles"][role_name]["inherited_roles"] = inherited_roles
    
    # 3. Create/Update Access Policy Definition
    if "access" not in org["defined_policies"]:
        org["defined_policies"]["access"] = {}
        
    # Parse permissions
    api_permissions = {}
    if perms_json:
        try:
            raw_perms = json.loads(perms_json)
            # Format: [{"path": "/foo", "actions": ["read", "write"]}]
            for item in raw_perms:
                path = item.get("path")
                actions = item.get("actions", [])
                if path and actions:
                    api_permissions[path] = actions
        except json.JSONDecodeError:
            return "Invalid Permissions JSON", 400
            
    # Save Policy Config
    policy_config = {
        "api_permissions": api_permissions,
        # Backward compat fields derived
        "prefixes": list(api_permissions.keys()),
        "permissions": ["read", "write"] 
    }
    
    org["defined_policies"]["access"][policy_id] = policy_config
    
    save_data(data)
    return redirect(url_for("org_details", org_id=org_id))

@app.route("/org/<org_id>/roles/delete", methods=["POST"])
def delete_role(org_id):
    role_name = request.form.get("role_name")
    data = load_data()
    org = data["organizations"].get(org_id)
    
    if role_name and role_name in org.get("roles", {}):
        # Optional: delete associated policy?
        # policy_id = org["roles"][role_name]["assigned_policies"].get("access")
        # if policy_id: del org["defined_policies"]["access"][policy_id]
        
        del org["roles"][role_name]
        save_data(data)
        
    return redirect(url_for("org_details", org_id=org_id))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8182, debug=False) # Configured port for dev
