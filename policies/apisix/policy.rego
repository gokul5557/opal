package policies.apisix.policy

import data.policies.security.ip_whitelist
import data.policies.common.inheritance
import future.keywords.if
import future.keywords.in

# Default Deny
default allow = false

# -----------------------------------------------------------------------------
# 1. Public / Shared Paths (Always Allowed)
# -----------------------------------------------------------------------------
params := input.request
path := params.path
method := params.method
# Production: Extract User from X-Userinfo header
user_email := email if {
    v := input.request.headers["X-Userinfo"]
    dec := base64.decode(v)
    obj := json.unmarshal(dec)
    email := obj.email
}

allow if {
    is_public_path
}

is_public_path if startswith(path, "/auth")
is_public_path if startswith(path, "/logout")
is_public_path if startswith(path, "/callback")
is_public_path if startswith(path, "/health")
is_public_path if method == "OPTIONS"

# -----------------------------------------------------------------------------
# 2. Authenticated Access Check
# -----------------------------------------------------------------------------
allow if {
    # User must be authenticated
    user_email != null
    
    # Check IP Whitelist (Explicitly pass decoded user_email)
    ip_whitelist.allow_user(user_email)
    
    # Get Effective Access Configuration (Merged) (Explicitly pass user_email)
    config := inheritance.get_effective_config_merged_with_user("access", user_email)
    
    # Check Permissions (Read/Write)
    has_permission(config.permissions, method)
    
    # Check Path Prefix
    has_prefix_access(config.prefixes, path)
}

# Helper: Check Method Permission
has_permission(perms, m) if {
    m == "GET"
    "read" in perms
}
has_permission(perms, m) if {
    m in ["POST", "PUT", "DELETE", "PATCH"]
    "write" in perms
}

# Helper: Check Prefix
has_prefix_access(prefixes, p) if {
    some allowed_prefix in prefixes
    startswith(p, allowed_prefix)
}

# -----------------------------------------------------------------------------
# 3. Denial Reasons (for debugging/testing)
# -----------------------------------------------------------------------------
deny[reason] if {
    # Check IP Whitelist Denials (Explicit user)
    reasons := ip_whitelist.get_deny_reasons(user_email)
    reason := reasons[_]
}

deny[reason] if {
    # Check Access Denials
    user_email != null
    # Only check if IP passed
    ip_whitelist.allow_user(user_email)
    
    config := inheritance.get_effective_config_merged_with_user("access", user_email)
    
    # Check 1: Permission
    not has_permission(config.permissions, method)
    reason := sprintf("Method %v not allowed (Effective Perms: %v)", [method, config.permissions])
}

deny[reason] if {
    # Check Access Denials
    user_email != null
    ip_whitelist.allow_user(user_email)
    
    config := inheritance.get_effective_config_merged_with_user("access", user_email)
    
    # Check 2: Prefix
    not has_prefix_access(config.prefixes, path)
    reason := sprintf("Path %v not allowed (Allowed Prefixes: %v)", [path, config.prefixes])
}
