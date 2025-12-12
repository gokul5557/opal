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

# -----------------------------------------------------------------------------
# Additive Merge Logic (For Access Control / APISIX)
# Hierarchy: Union(Org + Dept + Groups + User) -> All permissions apply
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Additive Merge Logic (For Access Control / APISIX)
# Hierarchy: Union(Org + Dept + Groups + ResolvedRoles + User)
# -----------------------------------------------------------------------------

# Helper: Resolve full list of roles recursively (Role Inheritance)
resolve_all_roles(org_roles, user_roles) := all_roles if {
    # Build Graph: role_name -> [inherited_role_names]
    # nodes are keys of org_roles
    # edges are org_roles[r].inherited_roles
    
    # graph.reachable algo expects graph as {node: [neighbors]}
    # We construct this from org_roles.
    role_graph := {r_name: inheritance | 
        some r_name, r_config in org_roles
        inheritance := object.get(r_config, "inherited_roles", [])
    }
    
    # Calculate reachability from user's direct roles
    all_roles := graph.reachable(role_graph, user_roles)
}

# Helper: Normalize policy config to granular api_permissions map
# Returns { "/path": {"read", "write"} }
normalize_permissions(policy) := perms_map if {
    # 1. Existing Granular Permissions
    existing_granular := object.get(policy, "api_permissions", {})
    
    # 2. Legacy Prefix-based Permissions (convert to granular)
    # Check "prefixes" OR "allowed_prefixes" (older legacy)
    p1 := object.get(policy, "prefixes", [])
    p2 := object.get(policy, "allowed_prefixes", [])
    legacy_prefixes := array.concat(p1, p2)
    
    # Check "permissions" (default to read/write if not present)
    legacy_perms := object.get(policy, "permissions", ["read", "write"])
    
    legacy_granular := {p: {x | some x in legacy_perms} | some p in legacy_prefixes}
    
    # 3. Merge both (Legacy wins/adds to granular if same path? Union is safer)
    # We want union of permissions for each path
    all_paths := object.keys(existing_granular) | object.keys(legacy_granular)
    
    perms_map := {path: final_perms |
        some path in all_paths
        p1 := object.get(existing_granular, path, set())
        p2 := object.get(legacy_granular, path, set())
        # Ensure p1/p2 are sets (if json array)
        s1 := {x | some x in p1}
        s2 := {x | some x in p2}
        final_perms := s1 | s2
    }
}

get_effective_config_merged(policy_type) := get_effective_config_merged_with_user(policy_type, input.user)

get_effective_config_merged_with_user(policy_type, user_email) := merged_config if {
    # user_email passed as arg
    user := object.get(data.users, user_email, {})
    org := object.get(data.organizations, object.get(user, "org_id", ""), {})
    
    # 1. Defined Policies Lookup
    defined_policies_type := object.get(object.get(org, "defined_policies", {}), policy_type, {})
    
    # 2. Collect all raw policy configs
    # Org
    org_policy_id := object.get(object.get(org, "assigned_policies", {}), policy_type, "")
    org_policy := object.get(defined_policies_type, org_policy_id, {})

    # Dept
    dept := object.get(object.get(org, "departments", {}), object.get(user, "dept_id", ""), {})
    dept_policy_id := object.get(object.get(dept, "assigned_policies", {}), policy_type, "")
    dept_policy := object.get(defined_policies_type, dept_policy_id, {})
    
    # Groups
    user_groups := object.get(user, "groups", [])
    group_policies := [gp |
        some group_name in user_groups
        group := object.get(object.get(org, "groups", {}), group_name, {})
        grp_policy_id := object.get(object.get(group, "assigned_policies", {}), policy_type, "")
        gp := object.get(defined_policies_type, grp_policy_id, {})
    ]

    # Roles (Resolved Recursively)
    direct_roles := object.get(user, "roles", [])
    all_role_names := resolve_all_roles(object.get(org, "roles", {}), direct_roles)
    
    role_policies := [rp |
        some role_name in all_role_names
        role := object.get(object.get(org, "roles", {}), role_name, {})
        rp_id := object.get(object.get(role, "assigned_policies", {}), policy_type, "")
        rp := object.get(defined_policies_type, rp_id, {})
    ]

    # User Override
    user_override := object.get(object.get(user, "policy_overrides", {}), policy_type, {})
    
    # 3. Merge Strategy: Union of API Permissions
    # Flatten all configs
    input_configs := array.concat([org_policy, dept_policy, user_override], group_policies)
    all_configs := array.concat(input_configs, role_policies)
    
    # Normalize and Merge ALL
    # We iterate all configs, normalize them to maps, and merge the maps
    all_perm_maps := [m | some cfg in all_configs; m := normalize_permissions(cfg)]
    
    # Union of all keys (paths) across all maps
    all_paths := {path | some m in all_perm_maps; some path, _ in m}
    
    final_api_permissions := {path: total_perms |
        some path in all_paths
        # Gather perms for this path from all maps
        perms_list := [p | some m in all_perm_maps; p := object.get(m, path, set())]
        # Flatten sets
        total_perms := {x | some s in perms_list; some x in s}
    }
    
    merged_config := {
        "api_permissions": final_api_permissions,
        # Keep legacy formats populated for UI/Consumer backward compatibility if needed?
        # Let's derive them:
        "prefixes": [p | some p, _ in final_api_permissions],
        "permissions": ["read", "write"] # Broad catch-all, mainly legacy consumers check this
    }
}

explain_config_merged(policy_type) := explain_config_merged_with_user(policy_type, input.user)

explain_config_merged_with_user(policy_type, user_email) := trace if {
    # user_email arg
    user := object.get(data.users, user_email, {})
    org := object.get(data.organizations, object.get(user, "org_id", ""), {})
    defined_policies_type := object.get(object.get(org, "defined_policies", {}), policy_type, {})
    
    # ... (Re-fetch logic similar to above for explanation structure)
    org_policy_id := object.get(object.get(org, "assigned_policies", {}), policy_type, "")
    org_policy := object.get(defined_policies_type, org_policy_id, {})

    dept := object.get(object.get(org, "departments", {}), object.get(user, "dept_id", ""), {})
    dept_policy_id := object.get(object.get(dept, "assigned_policies", {}), policy_type, "")
    dept_policy := object.get(defined_policies_type, dept_policy_id, {})
    
    user_groups := object.get(user, "groups", [])
    group_policies := [gp |
        some group_name in user_groups
        group := object.get(object.get(org, "groups", {}), group_name, {})
        grp_policy_id := object.get(object.get(group, "assigned_policies", {}), policy_type, "")
        gp_data := object.get(defined_policies_type, grp_policy_id, {})
        gp := {"group": group_name, "policy_id": grp_policy_id, "config": gp_data}
    ]

    direct_roles := object.get(user, "roles", [])
    all_role_names := resolve_all_roles(object.get(org, "roles", {}), direct_roles)
    
    role_policies := [rp |
        some role_name in all_role_names
        role := object.get(object.get(org, "roles", {}), role_name, {})
        rp_id := object.get(object.get(role, "assigned_policies", {}), policy_type, "")
        rp_data := object.get(defined_policies_type, rp_id, {})
        
        # Mark if inherited
        inherited := count({x | x := role_name; x in direct_roles}) == 0
        
        rp := {
            "role": role_name, 
            "policy_id": rp_id, 
            "config": rp_data,
            "inherited": inherited
        }
    ]

    user_policy := object.get(object.get(user, "policy_overrides", {}), policy_type, {})
    effective := get_effective_config_merged_with_user(policy_type, user_email)

    trace := {
        "org_policy": {"id": org_policy_id, "config": org_policy},
        "dept_policy": {"id": dept_policy_id, "config": dept_policy},
        "group_policies": group_policies,
        "role_policies": role_policies,
        "user_policy": {"config": user_policy},
        "effective": effective
    }
}

# -----------------------------------------------------------------------------
# IP Whitelist Merge Logic (Union of CIDRs)
# -----------------------------------------------------------------------------
get_effective_ip_whitelist_merged(policy_type) := get_effective_ip_whitelist_merged_with_user(policy_type, input.user)

get_effective_ip_whitelist_merged_with_user(policy_type, user_email) := merged_config if {
    # user_email arg
    user := object.get(data.users, user_email, {})
    org := object.get(data.organizations, object.get(user, "org_id", ""), {})
    
    # 1. Defined Policies Lookup
    defined_policies_type := object.get(object.get(org, "defined_policies", {}), policy_type, {})
    
    # 2. Collect all raw policy configs
    # Org
    org_policy_id := object.get(object.get(org, "assigned_policies", {}), policy_type, "")
    org_policy := object.get(defined_policies_type, org_policy_id, {})

    # Dept
    dept := object.get(object.get(org, "departments", {}), object.get(user, "dept_id", ""), {})
    dept_policy_id := object.get(object.get(dept, "assigned_policies", {}), policy_type, "")
    dept_policy := object.get(defined_policies_type, dept_policy_id, {})
    
    # Groups
    user_groups := object.get(user, "groups", [])
    group_policies := [gp |
        some group_name in user_groups
        group := object.get(object.get(org, "groups", {}), group_name, {})
        grp_policy_id := object.get(object.get(group, "assigned_policies", {}), policy_type, "")
        gp := object.get(defined_policies_type, grp_policy_id, {})
    ]

    # Roles (Resolved Recursively)
    direct_roles := object.get(user, "roles", [])
    all_role_names := resolve_all_roles(object.get(org, "roles", {}), direct_roles)
    
    role_policies := [rp |
        some role_name in all_role_names
        role := object.get(object.get(org, "roles", {}), role_name, {})
        rp_id := object.get(object.get(role, "assigned_policies", {}), policy_type, "")
        rp := object.get(defined_policies_type, rp_id, {})
    ]

    # User Override
    user_override := object.get(object.get(user, "policy_overrides", {}), policy_type, {})
    
    # 3. Merge Strategy: Union of 'allow_cidrs'
    # Flatten all configs
    input_configs := array.concat([org_policy, dept_policy, user_override], group_policies)
    all_configs := array.concat(input_configs, role_policies)
    
    # Extract all CIDRs
    all_cidrs := {cidr |
        some cfg in all_configs
        some cidr in object.get(cfg, "allow_cidrs", [])
    }
    
    merged_config := {
        "allow_cidrs": all_cidrs
    }
}
