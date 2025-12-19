package policies.security.mfa

import data.policies.common.inheritance
import future.keywords.if
import future.keywords.in

# Default: MFA not satisfied (deny access if checking strict 'allow')
# But mostly we return 'config' for the app to decide.
default allow = false

# Allow if NOT required
allow if {
    config := inheritance.get_effective_mfa_config("mfa")
    config.required == false
}

# Allow if required AND satisfied (Need input.auth_method or similar?)
# For now, let's just expose the CONFIG so the app knows what to ask for.

# Expose the effective configuration
config := inheritance.get_effective_config("mfa")
config := c if {
    c := inheritance.get_effective_mfa_config("mfa")
}

# Helper to check if a specific method is allowed for this user
is_method_allowed(method) if {
    c := config
    method in c.methods
}
