package mail_service.password

import future.keywords.if
import future.keywords.in

default allow := false

# Main Entry: Validate password via input (for API testing)
allow if {
    validate(input.user_id, input.password)
}

# Function: Validate password against hierarchical policy
validate(user_id, password) if {
    org_id := get_org_id(user_id)
    policy := get_password_policy(org_id, user_id)
    
    count(password) >= policy.password_min_length
    check_rules(policy, password)
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

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

check_rules(policy, pwd) if {
    # Optional logic for numbers/special chars
    not policy.password_require_number
} else if {
    policy.password_require_number
    re_match(`[0-9]`, pwd)
}

# (Add more rule checks as needed)
