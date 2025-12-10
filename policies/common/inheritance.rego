package policies.common.inheritance

import future.keywords.if
import future.keywords.in

# -----------------------------------------------------------------------------
# Data Lookups & Merging Logic
# -----------------------------------------------------------------------------

# Helper: Get effective configuration for a specific policy type (e.g. "security", "access", "ip_whitelist")
# Hierarchy: Org < Dept < Group < User
get_effective_config(policy_type) := merged_config if {
    user_email := input.user
    user := object.get(data.users, user_email, {})
    org := object.get(data.organizations, object.get(user, "org_id", ""), {})
    
    # Safe lookups
    dept := object.get(object.get(org, "departments", {}), object.get(user, "dept_id", ""), {})
    user_groups := object.get(user, "groups", [])
    
    # 1. Base Policies (Org, Dept)
    org_policy := object.get(object.get(org, "policy", {}), policy_type, {})
    dept_policy := object.get(object.get(dept, "policy", {}), policy_type, {})
    
    # 2. Group Policies
    group_policies := [gp |
        some group_name in user_groups
        # Get Group Object safely
        group := object.get(object.get(org, "groups", {}), group_name, {})
        # Get Policy safely
        gp := object.get(object.get(group, "policy", {}), policy_type, {})
    ]

    # 3. User Override
    user_policy := object.get(object.get(user, "policy_override", {}), policy_type, {})
    
    # 4. Construct List (Org -> Dept -> Groups -> User)
    layers := array.concat([org_policy, dept_policy], group_policies)
    final_layers := array.concat(layers, [user_policy])
    
    # 5. Merge
    merged_config := object.union_n(final_layers)
}
