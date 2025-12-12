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
# Legacy: User is passed explicitly in input
user_email := input.user

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
    
    # Check IP Whitelist (uses input.user implicitly via legacy wrapper)
    ip_whitelist.allow
    
    # Get Effective Access Configuration (Merged) (uses input.user implicitly)
    config := inheritance.get_effective_config_merged("access")
    
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
    # Check IP Whitelist Denials
    ip_whitelist.deny[reason]
}

deny[reason] if {
    # Check Access Denials
    user_email != null
    # Only check if IP passed
    ip_whitelist.allow
    
    config := inheritance.get_effective_config_merged("access")
    
    # Check 1: Permission
    not has_permission(config.permissions, method)
    reason := sprintf("Method %v not allowed (Effective Perms: %v)", [method, config.permissions])
}

deny[reason] if {
    # Check Access Denials
    user_email != null
    ip_whitelist.allow
    
    config := inheritance.get_effective_config_merged("access")
    
    # Check 2: Prefix
    not has_prefix_access(config.prefixes, path)
    reason := sprintf("Path %v not allowed (Allowed Prefixes: %v)", [path, config.prefixes])
}
