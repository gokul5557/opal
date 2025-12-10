package policies.security.mfa

import future.keywords.if
import future.keywords.in
import data.policies.common.inheritance

# Entry point for MFA check
# Input expected: {"user": "email"}
required if {
    # 1. Get Effective Config
    config := inheritance.get_effective_config("security")
    
    # 2. Check Requirement
    # Default to false if not specified
    object.get(config, "mfa_required", false) == true
}
