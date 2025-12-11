package policy

import future.keywords.if
import future.keywords.in

# -----------------------------------------------------------------------------
# Test: Alice (Developer + Manager Override)
# Expectations:
# - MFA: True (Inherited from Engineering Dept)
# - Password: 12 (Inherited from Engineering Dept - stricter than Org)
# - Access: Union of Org, Dept, Role, and User Override
# -----------------------------------------------------------------------------
test_alice_policy if {
    # Simulate Input
    inp := {"user": "alice@acme.com"}
    
    # Evaluate
    res := effective_policy with input as inp
    
    # Assertions
    res.security.mfa_required == true
    res.security.password_min_length == 12
    
    # Check Access (Should have all)
    "/public" in res.access.allowed_prefixes        # Org
    "/git" in res.access.allowed_prefixes           # Dept
    "/dev-env" in res.access.allowed_prefixes       # Role: Developer
    "/special-project" in res.access.allowed_prefixes # User Override
}

# -----------------------------------------------------------------------------
# Test: Charlie (Sales)
# Expectations:
# - MFA: False (Not set in Dept or Org)
# - Password: 8 (Org Default)
# - Session: 240 (Sales Dept is stricter than Org 1440)
# -----------------------------------------------------------------------------
test_charlie_policy if {
    inp := {"user": "charlie@acme.com"}
    res := effective_policy with input as inp
    
    res.security.mfa_required == false
    res.security.password_min_length == 8
    res.security.session_timeout_minutes == 240
    
    "/crm" in res.access.allowed_prefixes
}

# -----------------------------------------------------------------------------
# Test: Dave (Startup Inc)
# Expectations:
# - MFA: True (Org Level)
# - Password: 10 (Org Level)
# -----------------------------------------------------------------------------
test_dave_policy if {
    inp := {"user": "dave@startup.com"}
    res := effective_policy with input as inp
    
    res.security.mfa_required == true
    res.security.password_min_length == 10
}
