package policies.access.ip_whitelist

import future.keywords.if
import future.keywords.in
import data.policies.common.inheritance

# Entry point
# Input expected: {"user": "email", "ip": "1.2.3.4"}
deny[reason] if {
    # 1. Get Effective Config
    config := inheritance.get_effective_config("ip_whitelist")
    
    # 2. Get Allowed CIDRs
    # Default to allow all if not specified? Or deny all? 
    # Usually whitelist means strict. Let's default to ["0.0.0.0/0"] (Allow All) for POC unless overridden.
    allowed_cidrs := object.get(config, "allowed_cidrs", [])
    
    count(allowed_cidrs) > 0
    
    # 3. Check if IP matches ANY allowed CIDR
    matches := [cidr | 
        some cidr in allowed_cidrs
        net.cidr_contains(cidr, input.ip)
    ]
    
    count(matches) == 0
    
    reason := sprintf("Access denied from IP %s. Allowed networks: %v", [input.ip, allowed_cidrs])
}
