# Policy Manager: Developer Handover & Implementation Guide

This document provides technical instructions for the development team to build, maintain, and scale the **Policy Manager** system.

---

## 1. Core Architecture: OPA & OPAL

The system uses **Open Policy Agent (OPA)** for decoupled authorization. 

*   **Rego (Policies)**: The logic layer. It defines *who* can do *what*. 
*   **JSON (Data)**: The state layer. It defines users, their roles, and organization settings.
*   **OPAL (Update Layer)**: Synchronizes the JSON data from Git to OPA in real-time.

### The Decision Flow
1. **Backend** sends a query: `{ "input": { "user": "alice@org.com", "path": "/api/inbox", "method": "GET" } }`.
2. **OPA** evaluates the `input` against the loaded **Rego logic** and **JSON data**.
3. **OPA** returns `allow: true` or `false`.

---

## 2. Directory Structure (Client Management)

The data is organized hierarchically to support multi-tenancy and scalability.

```text
mail_service/
└── policy_data/
    ├── global/
    │   └── data.json           # [GLOBAL] Universal Roles & Policies
    └── organizations/
        ├── Company_ABC/
        │   └── data.json       # [TENANT-1] Users, Roles, Config
        └── Org_Gamma/
            └── data.json       # [TENANT-2] Users, Roles, Config
```

### Adding a New Client
1. Create a folder: `mail_service/policy_data/organizations/{New_Org_ID}/`.
2. Create a file **strictly named** `data.json` inside it.
3. **Template for `data.json`**:
```json
{
  "plan": "pro_plan",
  "domains": { "example.com": { "status": "verified" } },
  "users": {
    "admin@example.com": {
      "name": "Admin Name",
      "roles": ["admin"],
      "status": "active"
    }
  },
  "assigned_policies": {
    "password": "strict"
  }
}
```

---

## 3. Role Assignment & Inheritance

### Global Inheritance
Local tenants inherit from `policy_data/global/data.json`.
*   **Global Roles**: `admin`, `user`.
*   **Global Policies**: `strict` (Password), `global_admin_access` (Access).

### How to Assign Roles
Assignments happen in the `users` block of the tenant's `data.json`.
*   **Use Global Role**: `"roles": ["admin"]` (inherited from global).
*   **Use Tenant Role**: Define `"roles": { "custom_role": { ... } }` in the local `data.json` and assign it.

### How to Override Policies
In the `assigned_policies` block:
*   `"password": "weak"` (Inherits global definition).
*   `"password": "local_strict"` (Uses a definition found in the tenant's `defined_policies`).

---

## 4. GitOps Workflow (Python Integration)

The Policy Manager (UI) acts as a **CMS**. It edits a **Local SQLite DB** and "Publishes" to the **Git Repo**.

### Automatic Push to Git
Use the following logic to commit changes from Python:
```python
import subprocess

def push_to_git(repo_dir, commit_message):
    try:
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
        subprocess.run(["git", "commit", "-m", commit_message], cwd=repo_dir, check=True)
        subprocess.run(["git", "push"], cwd=repo_dir, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Git failed: {e}")
        return False
```

---

## 5. Testing & Verification

### Targeted Verification
We have implemented a `tester.py` utility. To verify a policy change:
1. Call `tester.run_tests_for_org(org_id)`.
2. It constructs OPA `input` payloads for every user in that org.
3. It compares OPA's response against the **Expected result** (calculated locally based on rules).

### The "Dummy Server" Workflow
Developers MUST follow this safety loop:
1. **Deploy Dummy OPAL**: Run a standalone OPA/OPAL container pointed at a **Test Branch**.
2. **Push Trial Data**: Use the Policy Manager to push a new user/role to the Test Branch.
3. **Verify Decision**:
   ```bash
   curl -X POST http://localhost:8181/v1/data/mail_service/apisix/allow \
     -d '{"input": {"request": {"path": "/api", "method": "GET", "headers": {"X-Userinfo": "..."}}}}'
   ```
4. **Merge to Main**: Once tests pass and OPA doesn't crash, merge the branch to the production repo.

---

## 6. Developer Checklist for Implementation

- [ ] **DB Layer**: Use SQLite to store "Draft" states of Users/Orgs.
- [ ] **Serializers**: Write functions to convert relational DB rows back into the nested JSON format.
- [ ] **Validation Layer**: Before pushing to Git, run `opa check policies/` via subprocess to ensure no syntax errors.
- [ ] **Git Hook**: Ensure the Python environment has SSH keys configured to push to the remote repo.
- [ ] **Audit Logs**: Every push should record *Who* changed *What* in a separate log file or DB table.
