package policies.security.ip_whitelist

import data.policies.common.inheritance
import future.keywords.if
import future.keywords.in

# Default checked by APISIX policy
default allow = false

# IP Whitelist Logic
# 1. Get Effective Config (Union of all allowed CIDRs)
# 2. Check if input.ip is in ANY of the allowed CIDRs.
# 3. If "allow_cidrs" is empty, it means NO whitelist is enforced (Default Allow? Or Default Deny?)
#    - Standard practice: If whitelist defined, enforce it. If empty, allow all (unless restricted elsewhere).
#    - Let's assume: If allow_cidrs is NOT empty, verify input.ip. If empty, allow.

# Default usage (using input.user)
allow if allow_user(input.user)

# Parameterized usage
allow_user(user_email) if {
    # If no CIDRs are defined, we likely want to pass (allow)
    config := inheritance.get_effective_ip_whitelist_merged_with_user("ip_whitelist", user_email)
    count(config.allow_cidrs) == 0
}

allow_user(user_email) if {
    config := inheritance.get_effective_ip_whitelist_merged_with_user("ip_whitelist", user_email)
    some cidr in config.allow_cidrs
    net.cidr_contains(cidr, input.var.remote_addr)
}

# Legacy rule for backward compat (if called directly without arg)
effective_config := inheritance.get_effective_ip_whitelist_merged("ip_whitelist")

allow if {
    # If no CIDRs are defined, we likely want to pass (allow)
    count(effective_config.allow_cidrs) == 0
}

allow if {
    # If CIDRs are defined, input.ip MUST be in at least one
    some cidr in effective_config.allow_cidrs
    net.cidr_contains(cidr, input.ip)
}

# Debug/Trace
# Debug/Trace
deny[reason] if {
    reasons := get_deny_reasons(input.user)
    reason := reasons[_]
}

get_deny_reasons(user_email) = reasons if {
    reasons := { r |
        config := inheritance.get_effective_ip_whitelist_merged_with_user("ip_whitelist", user_email)
        count(config.allow_cidrs) > 0
        not ip_in_whitelist_config(config)
        r := sprintf("IP %v is not whitelisted", [input.var.remote_addr])
    }
}

ip_in_whitelist_config(config) if {
    some cidr in config.allow_cidrs
    net.cidr_contains(cidr, input.var.remote_addr)
}

ip_in_whitelist if {
    some cidr in effective_config.allow_cidrs
    net.cidr_contains(cidr, input.ip)
}
