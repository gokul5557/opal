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
    
    # 1. Get Defined Policies for this TYPE (e.g. org.defined_policies.password)
    defined_policies_type := object.get(object.get(org, "defined_policies", {}), policy_type, {})
    
    # 2. Org Policy
    # Look for org.assigned_policies.password -> ID
    org_policy_id := object.get(object.get(org, "assigned_policies", {}), policy_type, "")
    org_policy := object.get(defined_policies_type, org_policy_id, {})

    # 3. Dept Policy
    dept := object.get(object.get(org, "departments", {}), object.get(user, "dept_id", ""), {})
    dept_policy_id := object.get(object.get(dept, "assigned_policies", {}), policy_type, "")
    dept_policy := object.get(defined_policies_type, dept_policy_id, {})
    
    # 4. Group Policies
    user_groups := object.get(user, "groups", [])
    group_policies := [gp |
        some group_name in user_groups
        group := object.get(object.get(org, "groups", {}), group_name, {})
        
        grp_policy_id := object.get(object.get(group, "assigned_policies", {}), policy_type, "")
        gp := object.get(defined_policies_type, grp_policy_id, {})
    ]

    # 5. User Overrides (Direct values still, or referenced? Generator says unused for now)
    # Let's support inline overrides for ultimate flexibility
    user_policy := object.get(object.get(user, "policy_overrides", {}), policy_type, {})
    
    layers := array.concat([org_policy, dept_policy], group_policies)
    final_layers := array.concat(layers, [user_policy])
    
    merged_config := object.union_n(final_layers)
}

# Helper: Explain configuration resolution for debugging/UI
explain_config(policy_type) := explanation if {
    user_email := input.user
    user := object.get(data.users, user_email, {})
    org := object.get(data.organizations, object.get(user, "org_id", ""), {})
    
    # 1. Get Defined Policies
    defined_policies_type := object.get(object.get(org, "defined_policies", {}), policy_type, {})
    
    # 2. Org Policy
    org_policy_id := object.get(object.get(org, "assigned_policies", {}), policy_type, "")
    org_policy := object.get(defined_policies_type, org_policy_id, {})

    # 3. Dept Policy
    dept := object.get(object.get(org, "departments", {}), object.get(user, "dept_id", ""), {})
    dept_policy_id := object.get(object.get(dept, "assigned_policies", {}), policy_type, "")
    dept_policy := object.get(defined_policies_type, dept_policy_id, {})
    
    # 4. Group Policies
    user_groups := object.get(user, "groups", [])
    group_policies := [gp |
        some group_name in user_groups
        group := object.get(object.get(org, "groups", {}), group_name, {})
        
        grp_policy_id := object.get(object.get(group, "assigned_policies", {}), policy_type, "")
        gp_data := object.get(defined_policies_type, grp_policy_id, {})
        
        gp := {
            "group": group_name,
            "policy_id": grp_policy_id,
            "config": gp_data
        }
    ]

    # 5. User Overrides
    user_policy := object.get(object.get(user, "policy_overrides", {}), policy_type, {})
    
    # 6. Effective
    # Re-calculate effective using the same logic as get_effective_config
    # (We could call get_effective_config but we want to be sure it matches these layers)
    layers := array.concat([org_policy, dept_policy], [gp.config | gp := group_policies[_]])
    final_layers := array.concat(layers, [user_policy])
    effective := object.union_n(final_layers)

    explanation := {
        "org_policy": {"id": org_policy_id, "config": org_policy},
        "dept_policy": {"id": dept_policy_id, "config": dept_policy},
        "group_policies": group_policies,
        "user_policy": {"config": user_policy},
        "effective": effective
    }
}
