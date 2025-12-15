# 02. Policy Hierarchy & Inheritance Deep Dive

## 2.1 The Philosophy: "Additive Union"
The core philosophy of this authorization framework is **Additive Permissions**.
*   We calculate the **Union** of all permissions assigned to a user from various sources.
*   If *any* source grants access to a resource, the user has access (unless explicitly denied by a Blocklist, though currently we focus on Allow-lists).

## 2.2 The Hierarchy Layers
When OPA evaluates a request for `alice@sagasoft.io`, it gathers configuration from these layers:

### Layer 1: Global Defaults
*   **Scope**: Applies to EVERYONE in the system.
*   **Purpose**: Baseline access (e.g., standard Employee access to Mail).
*   **Source**: `data.global_policies`.
*   **Example**: "All users get Read/Write on `/public`".

### Layer 2: Organization Level (`Org_1`)
*   **Scope**: Everyone in a specific tenant/organization.
*   **Purpose**: Plan-based limits (Basic vs Enterprise) or Corp-wide rules.
*   **Source**: `data.organizations["Org_1"].assigned_policies`.
*   **Example**: "Enterprise Plan grants access to /chat".

### Layer 3: Department Level (`Engineering`)
*   **Scope**: Users in a specific Department.
*   **Purpose**: Functional access.
*   **Source**: `data.organizations["Org_1"].departments["Engineering"].assigned_policies`.
*   **Example**: "Engineering Dept gets access to `/gitlab`".

### Layer 4: Group Level (`Team_Alpha`)
*   **Scope**: Ad-hoc groups of users (can be multiple).
*   **Purpose**: Project-specific or Team-specific access.
*   **Source**: `data.organizations["Org_1"].groups["Team_Alpha"].assigned_policies`.
*   **Example**: "Team Alpha gets access to `/project_alpha_files`".

### Layer 5: Role Level (`Employee`, `Admin`)
*   **Scope**: Assigned Roles (can be multiple).
*   **Purpose**: Functional capabilities, often spanning departments.
*   **Inheritance**: Roles can inherit from other roles.
    *   *Example*: `Manager` inherits `Employee`. `Employee` inherits `Basic_User`.
    *   OPA traverses this graph recursively to find *all* active roles.
*   **Source**: `data.users["alice"].roles` resolved against `data.organizations["Org_1"].roles` (and Global Roles).

### Layer 6: User Overrides
*   **Scope**: Specific individual.
*   **Purpose**: Exception management or temporary access.
*   **Source**: `data.users["alice"].policy_overrides`.
*   **Example**: "Grant Alice specific access to `/audit-logs` purely as an exception".

## 2.3 Inheritance Mechanics (`inheritance.rego`)

The magic happens in `get_effective_config_merged_with_user`.

1.  **Collection**: The function iterates through all the layers above.
    ```rego
    layers := [Org_Policy, Dept_Policy, Group_Policies..., Role_Policies..., User_Overrides]
    ```
2.  **Normalization**: Each policy might define permissions differently (Legacy `prefixes` list vs Granular `api_permissions` map).
    *   The code converts everything into a standard Map: `{ "/path/to/resource": {"read", "write"} }`.
3.  **Union (Merge)**:
    *   It merges all maps.
    *   If Layer A says `/mail` is `{"read"}` and Layer B says `/mail` is `{"write"}`, the result is `{"read", "write"}`.
    *   **Result**: The user gets the *sum* of all their privileges.

## 2.4 Use Cases

### Case A: The "Standard Employee"
*   **Global**: No special access.
*   **Org**: "Basic Plan" -> Access to `/mail` (Read/Write).
*   **Role**: "Employee" -> Access to `/intranet` (Read).
*   **Result**: Can use Mail and browse Intranet. Cannot access Admin DB.

### Case B: The "Billing Manager"
*   **Dept**: "Finance" -> Access to `/billing` (Read).
*   **Role**: "Billing_Admin" -> Access to `/billing` (Write), `/invoices` (Read/Write).
*   **Result**: Has full control over Billing/Invoices.

### Case C: The "Intern" (Global Restriction)
*   **Global**: "Intern_Policy" -> Only allow `/slack`.
*   *Note*: To implement "Restriction" (Deny), we mostly rely on simply *not granting* the other access. Since the default is Deny, if we only assign the "Intern Policy", they get nothing else.

## 2.5 Role Inheritance Example
You requested that "Everything is Employee".
1.  **User** has role `employee`.
2.  **Role Definition** (`employee`):
    *   `assigned_policies`: None (empty).
    *   `inherited_roles`: `["employee_apps"]`.
3.  **Role Definition** (`employee_apps`):
    *   `assigned_policies`: Grants access to `/mail`, `/drive`, `/calendar`.
4.  **Resolution**:
    *   OPA sees `employee`.
    *   OPA resolves inheritance -> `employee` + `employee_apps`.
    *   OPA merges policies from both.
    *   **Result**: User gets Mail/Drive/Calendar access.
