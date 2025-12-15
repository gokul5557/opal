# 04. Data Model & Configuration Guide

The `data.json` file is the Source of Truth for your authorization policy.

## 4.1 Global Sections

### `global_policies`
*   **What**: Standard Policy Definitions available to everyone.
*   **Structure**:
    ```json
    "global_policies": {
      "access": {
        "Global_Access_User": {
          "prefixes": ["/mail", "/drive"],
          "permissions": ["read", "write"]
        }
      }
    }
    ```
*   **Use**: Referenced by Roles or Orgs without re-writing the rule every time.

### `global_roles`
*   **What**: Standard Roles available to assign to any user.
*   **Structure**:
    ```json
    "global_roles": {
      "employee": {
        "assigned_policies": { "access": "access_role_employee" },
        "inherited_roles": ["employee_apps"]
      }
    }
    ```

## 4.2 Organization Structure

### `organizations["Org_1"]`
The container for a Tenant.

*   **`defined_policies`**: Custom policies specific to this Org.
*   **`assigned_policies`**: Policies applied to the *entire organization* (e.g., Default Plan).
*   **`departments`**:
    *   `"Engineering"`: Can have its own `assigned_policies`.
*   **`groups`**:
    *   `"Team_Alpha"`: Ad-hoc collections of users. Can have `assigned_policies`.
*   **`roles`**:
    *   Custom roles specific to this Org (e.g., "Org_1_Specific_Admin").

## 4.3 configuration Example: Adding a New Policy

**Goal**: Allow access to a new app `/new-app` for the "Research" department.

1.  **Define the Policy** (in `data.json` under `Org_1.defined_policies.access`):
    ```json
    "Policy_NewApp_Access": {
      "prefixes": ["/new-app"],
      "permissions": ["read", "write"]
    }
    ```

2.  **Assign to Department** (in `data.json` under `Org_1.departments.Research`):
    ```json
    "Research": {
      "assigned_policies": {
        "access": "Policy_NewApp_Access"
      }
    }
    ```

## 4.4 User Record (`users`)

The binding layer.

```json
"alice@sagasoft.io": {
  "org_id": "Org_1",
  "dept_id": "Research",
  "groups": ["Team_Alpha"],
  "roles": ["employee", "Researcher"],
  "policy_overrides": {
    "access": { ... } // Rare, emergency override
  }
}
```

*   **`org_id`**: Mandatory. Links user to the Tenant.
*   **`dept_id`**: Links to Dept Policy.
*   **`groups`**: Links to Group Policies.
*   **`roles`**: Links to Role Policies (and their inheritance).

## 4.5 Modifying Data
You have two options:
1.  **Policy Manager UI**: The safe, graphical way. (Preferred for day-to-day).
2.  **Direct JSON Edit**: Editing `data.json` directly.
    *   **Pro**: Fast, Bulk edits.
    *   **Con**: Easy to break syntax (missing commas).
    *   **Action**: After edit, simple `git commit` & `git push` (if using GitOps) or just save (if using local docker volume) will update OPAL.
