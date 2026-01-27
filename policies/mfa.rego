package mail_service.mfa

import future.keywords.if
import future.keywords.in

default allow := false

# Main Entry: Check if MFA requirements are met
allow_with_user(user_id) if {
    org_id := get_org_id(user_id)
    policy_def := get_mfa_policy(org_id, user_id)
    
    # If MFA is not required, allow
    not policy_def.mfa_required
} else if {
    # If MFA is required, check if user has verified MFA in session/input
    # (Assuming APISIX/OIDC provides this in a header or context)
    org_id := get_org_id(user_id)
    policy_def := get_mfa_policy(org_id, user_id)
    policy_def.mfa_required
    input.request.headers["X-Mfa-Verified"] == "true"
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

get_mfa_policy(org_id, user_id) := policy if {
    # 1. Check User Overrides? (Future)
    # 2. Check Org Level Default
    policy := data.organizations[org_id].assigned_policies.mfa
} else := policy if {
    # 3. Check Global Admin MFA if user is admin
    user := data.organizations[org_id].users[user_id]
    "admin" in user.roles
    policy := data.global.global_policies.mfa.admins_only
} else := policy if {
    # 4. Global Default
    policy := data.global.global_policies.mfa["default"]
}

get_org_id(user_id) := org_id if {
    some id, org in data.organizations
    org.users[user_id]
    org_id := id
}
