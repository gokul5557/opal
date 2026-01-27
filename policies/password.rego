package mail_service.password

import future.keywords.if
import future.keywords.in

default allow := false

# Main Entry: Validate password against hierarchical policy
validate(user_id, password) if {
    org_id := get_org_id(user_id)
    policy := get_password_policy(org_id)
    
    count(password) >= policy.password_min_length
    check_rules(policy, password)
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

get_password_policy(org_id) := policy if {
    # 1. Org Assigned Policy
    name := data.organizations[org_id].assigned_policies.password
    policy := data.organizations[org_id].defined_policies.password[name]
} else := policy if {
    # 2. Global Default
    policy := data.global.global_policies.password["default"]
}

get_org_id(user_id) := org_id if {
    some id, org in data.organizations
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
