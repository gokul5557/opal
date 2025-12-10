package policies.test

import future.keywords.if
import future.keywords.in

import data.policies.security.mfa
import data.policies.security.password

# -----------------------------------------------------------------------------
# Test MFA (Modular)
# -----------------------------------------------------------------------------

test_mfa_engineering_required if {
    # Alice (Engineering) -> MFA: True (from Dept)
    inp := {"user": "alice@acme.com"}
    data.policies.security.mfa.required with input as inp
}

test_mfa_sales_not_required if {
    # Charlie (Sales) -> MFA: False (Default)
    inp := {"user": "charlie@acme.com"}
    not data.policies.security.mfa.required with input as inp
}

test_mfa_startup_required if {
    # Dave (Startup) -> MFA: True (from Org)
    inp := {"user": "dave@startup.com"}
    data.policies.security.mfa.required with input as inp
}

# -----------------------------------------------------------------------------
# Test Password (Modular)
# -----------------------------------------------------------------------------

test_password_short_fail if {
    # Alice (Engineering) -> Requires 12 chars
    inp := {"user": "alice@acme.com", "password": "short"}
    
    reasons := data.policies.security.password.deny with input as inp
    count(reasons) > 0
    reasons["Password must be at least 12 characters long"]
}

test_password_long_pass if {
    # Alice (Engineering) -> Requires 12 chars + Number + Special Char
    inp := {"user": "alice@acme.com", "password": "SecurePassword123!"}
    
    reasons := data.policies.security.password.deny with input as inp
    count(reasons) == 0
}

test_password_default_pass if {
    # Charlie (Sales) -> Requires 8 chars + Number (Org Default)
    inp := {"user": "charlie@acme.com", "password": "mypassword1"}
    
    reasons := data.policies.security.password.deny with input as inp
    count(reasons) == 0
}

test_password_common_fail if {
    # Alice (Acme) -> Org has password_reject_common: true
    # "admin" is in common_passwords list
    inp := {"user": "alice@acme.com", "password": "admin"}
    
    reasons := data.policies.security.password.deny with input as inp
    count(reasons) > 0
    reasons["Password is too common/vulnerable"]
}
