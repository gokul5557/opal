package mail_service.apisix

import future.keywords.if
import future.keywords.in
import data.mail_service.access

# Default Deny
default allow := false

# 1. Public Paths (Always Allowed)
allow if is_public_path

# 2. Authenticated Access (Delegate to Access/MFA/Password)
allow if {
    not is_public_path
    user_email != null
    access.allow_with_user(user_email)
}

# -----------------------------------------------------------------------------
# User Extraction (Production Style)
# -----------------------------------------------------------------------------
user_email := email if {
    headers := input.request.headers
    v := object.get(headers, "X-Userinfo", object.get(headers, "x-userinfo", ""))
    v != ""
    dec := base64.decode(v)
    obj := json.unmarshal(dec)
    email := obj.email
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
is_public_path if {
    public_paths := ["/auth", "/health", "/callback", "/logout"]
    some p in public_paths
    startswith(input.request.path, p)
}

is_public_path if input.request.method == "OPTIONS"

# Deny Reasons
deny[reason] if {
    not is_public_path
    not allow
    reason := "Access Denied: Insufficient Permissions or Authentication Failure"
}
