package mail_service.password

import future.keywords.if
import future.keywords.in

default allow := false

# Main Entry: Allow if no deny reasons exist
allow if {
    # Ensure checking logic actually ran
    get_policy_context
    count(deny) == 0
}

# Fail Safe: Deny if policy context cannot be resolved
deny["System Error: Unable to resolve password policy for user"] if {
    not get_policy_context
}

# 1. Length Check
deny[reason] if {
    policy := get_policy_context
    min_len := object.get(policy, "password_min_length", 8)
    count(input.password) < min_len
    reason := sprintf("Password must be at least %d characters long", [min_len])
}

# 2. Number Check
deny[reason] if {
    policy := get_policy_context
    object.get(policy, "password_require_number", false) == true
    not re_match("[0-9]", input.password)
    reason := "Password must contain at least one number"
}

# 3. Special Character Check
deny[reason] if {
    policy := get_policy_context
    object.get(policy, "password_require_special_char", false) == true
    not re_match("[^A-Za-z0-9]", input.password)
    reason := "Password must contain at least one special character"
}

# 4. Uppercase Check
deny[reason] if {
    policy := get_policy_context
    object.get(policy, "password_require_uppercase", false) == true
    not re_match("[A-Z]", input.password)
    reason := "Password must contain at least one uppercase letter"
}

# 5. Lowercase Check
deny[reason] if {
    policy := get_policy_context
    object.get(policy, "password_require_lowercase", false) == true
    not re_match("[a-z]", input.password)
    reason := "Password must contain at least one lowercase letter"
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# Helper to fetch policy once per evaluation (context sensitive)
get_policy_context := policy if {
    # Ensure input has necessary fields
    input.user_id
    org_id := get_org_id(input.user_id)
    policy := get_password_policy(org_id, input.user_id)
}

get_password_policy(org_id, user_id) := policy if {
    # 1. Check User's Role-based Policy
    user := data.policy_data.organizations[org_id].users[user_id]
    some role_name in user.roles
    role := data.policy_data.organizations[org_id].roles[role_name]
    name := role.assigned_policies.password
    policy := data.policy_data.organizations[org_id].defined_policies.password[name]
} else := policy if {
    # 2. Org Assigned Policy (Fallback)
    name := data.policy_data.organizations[org_id].assigned_policies.password
    policy := data.policy_data.organizations[org_id].defined_policies.password[name]
} else := policy if {
    # 3. Global Default
    policy := data.policy_data.global.global_policies.password["default"]
}

get_org_id(user_id) := org_id if {
    some id, org in data.policy_data.organizations
    org.users[user_id]
    org_id := id
}
