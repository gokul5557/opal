# Understanding Your Production Policy (`current.rego`)

This document explains how your OPA policy works with APISIX OIDC data.

## 1. The Input Data (From APISIX)
APISIX sends a JSON payload to OPA. Based on your logs, the critical part is the `request.headers`:

```json
{
  "input": {
    "request": {
      "method": "GET",
      "path": "/mail/mail.api.account.get_user_info",
      "headers": {
        "X-Userinfo": "eyJzdWIiOiIxMzg1... (Base64 Encoded JSON) ...",
        "X-ID-Token": "...",
        "X-Access-Token": "..."
      }
    }
  }
}
```

*   **`X-Userinfo`**: This header is injected by the `openid-connect` plugin. It contains the user's details (email, groups, etc.) in a Base64 encoded JSON format.

## 2. Policy Logic Breakdown (`current.rego`)

### Step A: Extract User Information
The policy DOES NOT Look at the JWT (Access Token) directly. It trusts the `X-Userinfo` header populated by APISIX's OIDC plugin.

```rego
# Helper: Get User Email from Token
user_email := email if {
    # 1. Grab the Header
    user_info_header := input.request.headers["X-Userinfo"]
    
    # 2. Decode Base64
    user_info_json := base64.decode(user_info_header)
    
    # 3. Parse JSON
    user := json.unmarshal(user_info_json)
    
    # 4. Extract Email
    email := user.email
}
```
**Why this matters:** `base64.decode` is the magic step. If this header is missing or malformed, `user_email` becomes "undefined", and all access rules checking for `user_email` will effectively fail (deny).

### Step B: The Decision Flow (Allow Rules)

OPA evaluates multiple `allow` rules. If **ANY** of them match, the request is allowed (`allow = {"allow": true}`).

#### 1. Public Paths (No Auth Required)
Checks if the path starts with `/auth`, `/logout`, etc.
```rego
allow = {"allow": true} if { is_shared_path }
```

#### 2. Global Mail Access (Any Authenticated User)
If the user has a valid email (headers parsed successfully) AND the path starts with `/mail`, access is granted.
```rego
allow = {"allow": true} if {
    user_email          # Must be logged in
    startswith(path, "/mail")
}
```
*Note: This rule grants access to `/mail` for ANYONE with a valid token, ignoring granular permissions.*

#### 3. Granular Access (Other Services)
For other paths (e.g., `/drive`), it checks your configuration data:
```rego
allow = {"allow": true} if {
    user_config         # User matches data.app_config.users[email]
    has_permission      # Method matches (GET=Read, POST=Write)
    has_service_access  # Path matches user_config.prefixes
}
```

## 3. Data Dependency (`data.app_config.users`)
The policy relies on `data.app_config.users` being present in OPA's memory.
```rego
user_config := data.app_config.users[user_email]
```
If your OPA doesn't have the user's permissions loaded in `data.json` (under `app_config`), the specific access checks (Rule #3) will fail.

## Summary
1.  **APISIX** Authenticates user -> Injects `X-Userinfo`.
2.  **OPA** Decodes `X-Userinfo` -> Gets Email.
3.  **OPA** Checks:
    *   Is it public? -> **Allow**.
    *   Is it `/mail`? -> **Allow**.
    *   Is it configured in `data.json`? -> **Check Permissions & Prefix**.
4.  **Result**: Returns `{"result": {"allow": true}}` to APISIX.
