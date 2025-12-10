package policy

import future.keywords.if
import future.keywords.in

# Default Deny
default allow = false

# -----------------------------------------------------------------------------
# Input & Data Lookups
# -----------------------------------------------------------------------------

# Assume input.user contains the email, e.g., {"user": "alice@acme.com"}
user_email := input.user

# Lookup User Object
user := data.users[user_email]

# Lookup Organization
org := data.organizations[user.org_id]

# Lookup Department (if any)
dept := org.departments[user.dept_id]

# -----------------------------------------------------------------------------
# Policy Aggregation
# -----------------------------------------------------------------------------

# Gather all policies applicable to the user
policies[source] := policy if {
    # 1. Organization Policy
    policy := org.policy
    source := "organization"
}

policies[source] := policy if {
    # 2. Department Policy
    policy := dept.policy
    source := "department"
}

policies[source] := policy if {
    # 3. Role Policies
    some role_name in user.roles
    policy := dept.roles[role_name].policy
    source := concat(":", ["role", role_name])
}

policies[source] := policy if {
    # 4. User Override Policy
    policy := user.policy_override
    source := "user_override"
}

# -----------------------------------------------------------------------------
# Effective Policy Calculation
# -----------------------------------------------------------------------------

effective_policy := {
    "security": {
        "mfa_required": calculate_mfa,
        "password_min_length": calculate_password_length,
        "session_timeout_minutes": calculate_session_timeout
    },
    "access": {
        "allowed_prefixes": calculate_allowed_prefixes
    }
}

# Rule: MFA is required if ANY level requires it (Conservative / OR logic)
calculate_mfa := true if {
    some p in policies
    p.security.mfa_required == true
} else := false

# Rule: Password Length is MAX of all requirements (Most Secure)
calculate_password_length := max_val if {
    lengths := [l | some p in policies; l := p.security.password_min_length]
    count(lengths) > 0 # Ensure we have at least one value
    max_val := max(lengths)
} else := 8 # Default minimum if nothing specified

# Rule: Session Timeout is MIN of all requirements (Most Secure)
calculate_session_timeout := min_val if {
    timeouts := [t | some p in policies; t := p.security.session_timeout_minutes]
    count(timeouts) > 0
    min_val := min(timeouts)
} else := 60 # Default to 60 minutes if nothing specified

# Rule: Access Prefixes is UNION of all allowed lists (Additive)
calculate_allowed_prefixes := prefixes if {
    prefixes := {prefix | 
        some p in policies
        some prefix in p.access.allowed_prefixes
    }
}

# -----------------------------------------------------------------------------
# Access Control Decision (Example Usage)
# -----------------------------------------------------------------------------

# Allow if path starts with any allowed prefix
allow if {
    some prefix in effective_policy.access.allowed_prefixes
    startswith(input.path, prefix)
}
