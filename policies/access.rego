package mail_service.access

import future.keywords.if
import future.keywords.in

default allow := false

# Main Entry: Access Check with provided user_email
allow_with_user(user_id) if {
    # 1. Resolve Org ID
    org_id := get_org_id(user_id)

    # 2. Get User & Org Data
    user := data.organizations[org_id].users[user_id]
    
    # 3. Status Check
    user.status == "active"
    
    # 4. Role & Policy Resolution
    some role_name in user.roles
    role := data.organizations[org_id].roles[role_name]
    policy_name := role.assigned_policies.access
    
    # 5. Permission Lookup (Org > Global)
    policy_def := get_policy_def(org_id, policy_name)
    
    # 6. Action Verification
    path := input.request.path
    method := input.request.method
    check_permissions(policy_def.api_permissions, path, method)
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# Resolve Org ID for a user
get_org_id(user_id) := org_id if {
    some id, org in data.organizations
    org.users[user_id]
    org_id := id
}

# Get Access Policy Definition (Org > Global)
get_policy_def(org_id, policy_name) := def if {
    def := data.organizations[org_id].defined_policies.access[policy_name]
} else := def if {
    def := data.global.global_policies.access[policy_name]
}

# Verify Path & Method
check_permissions(perms, path, method) if {
    some pattern, allowed_actions in perms
    glob.match(pattern, ["/"], path)
    some action in allowed_actions
    action_matches_method(action, method)
}

# HTTP Method Mapping
action_matches_method("read", m)   if m in ["GET", "HEAD", "OPTIONS"]
action_matches_method("write", m)  if m in ["POST", "PUT", "PATCH", "DELETE"]
action_matches_method("create", m) if m == "POST"
action_matches_method("update", m) if m in ["PUT", "PATCH"]
action_matches_method("delete", m) if m == "DELETE"
