# 03. Rego Code Walkthrough

This section provides a detailed, line-by-line explanation of the key OPA policies.

## 3.1 `policies/apisix/policy.rego` (The Entry Point)

This file is the "Main" entry point that APISIX queries.

```rego
package policies.apisix.policy
```
**Line 1**: Defines the namespace. APISIX queries `data.policies.apisix.policy`.

```rego
# Default Deny
default allow = false
```
**Line 9**: **Security Best Practice**. Unless a rule explicitly says `allow = true`, the request is blocked.

### The "Public Path" Rule
```rego
allow if {
    is_public_path
}

is_public_path if startswith(path, "/auth")
# ...
```
**Logic**: Simple check. If the URL path starts with `/auth` (Login pages), let it through without checking headers.

### The "Authenticated Access" Rule (The Core Logic)
```rego
allow if {
    # 1. User must be authenticated
    user_email != null
    
    # 2. Check IP Whitelist
    ip_whitelist.allow_user(user_email)
    
    # 3. Get Effective Permissions
    config := inheritance.get_effective_config_merged_with_user("access", user_email)
    
    # 4. Check Permissions (Read/Write)
    has_permission(config.permissions, method)
    
    # 5. Check Path Prefix
    has_prefix_access(config.prefixes, path)
}
```
**Explanation**:
1.  **`user_email != null`**: Ensures we successfully parsed the `X-Userinfo` header. If the header was missing or invalid, this fails.
2.  **`ip_whitelist.allow_user`**: Calls the IP Policy module. "Is this user allowed from this IP?"
3.  **`get_effective_config...`**: Calls the massive Inheritance engine (see Doc 02). Returns a JSON object with allowed `prefixes` and `permissions`.
4.  **`has_permission`**: Checks if the HTTP Method (GET/POST) matches the allowed permissions (read/write).
5.  **`has_prefix_access`**: Checks if the requested URL (`/mail/api/...`) starts with one of the allowed prefixes (`/mail`).

## 3.2 `policies/security/ip_whitelist.rego`

This handles IP restrictions.

```rego
allow_user(user_email) if {
    # 1. Fetch Config
    config := inheritance.get_effective_ip_whitelist_merged_with_user("ip_whitelist", user_email)
    
    # 2. Check for Empty Config (Default Allow)
    count(config.allow_cidrs) == 0
}
```
**Logic**: usage of "Default Allow if Empty". If no IP Restrictions are configured for the user (or their Org/Role), then `allow_cidrs` is empty, and we **ALLOW** the request. We assume "No Config = No Restriction".

```rego
allow_user(user_email) if {
    config := ...
    # 3. Check Match
    some cidr in config.allow_cidrs
    net.cidr_contains(cidr, input.var.remote_addr)
}
```
**Logic**: If restrictions ARE configured, we require the request IP (`input.var.remote_addr`) to match *at least one* valid CIDR range (e.g. `10.0.0.0/8`).

## 3.3 `policies/common/inheritance.rego` (The Engine)

This is the complex engine. Key "Gotchas" and Fixes:

### Recursion Prevention
```rego
# Import specific data paths
import data.global_policies
import data.global_roles
# ... instead of 'import data'
```
**Lesson**: We specifically import sub-nodes of `data`. Importing the root `data` keyword caused a **Recursion Error** because OPA tried to re-evaluate the Policy (which IS code inside `data`) while evaluating the Rule.

### Direct Data Access
```rego
global_policies := object.get(data, "global_policies", {})
```
**Logic**: We read the raw JSON configuration loaded into memory. This is the bridge between the Static Code (`.rego`) and the Dynamic Data (`data.json`).

### Role Resolution (Graph Reachability)
```rego
resolve_all_roles(org_roles, user_roles) := all_roles if {
    # Build Graph: role_name -> [inherited_role_names]
    role_graph := {r_name: inheritance | ... }
    
    # Calculate reachability
    all_roles := graph.reachable(role_graph, user_roles)
}
```
**Logic**:
*   Builds a dependency graph of roles (Employee -> Employee_Apps).
*   Uses OPA's built-in `graph.reachable` to find ALL roles a user has, effectively "Walking the tree".
*   This is how assigning 1 role (`employee`) can grant 50 permissions from 5 different inherited sub-roles.
