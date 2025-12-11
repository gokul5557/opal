package policies.test.generated

import future.keywords.if
import future.keywords.in
import data.policies.access.ip_whitelist

# Helper to find a user in a specific group (Pick one)
find_user_in_group(group_name) := user_email if {
    # Get all users in the group
    users := [email | some email, user in data.users; group_name in object.get(user, "groups", [])]
    count(users) > 0
    user_email := users[0]
}

# Test: Remote Worker should have allowed IP 0.0.0.0/0 (Global Access)
# Even if Org is "high" strictness (limited IPs).
test_remote_worker_ip_access if {
    # 1. Find a user in "remote_workers" (if any)
    # This relies on random generation producing at least one. 
    # If not, we skip? In POC we assume probability is high enough.
    email := find_user_in_group("remote_workers")
    
    # 2. Test execution
    # Any IP should pass
    inp := {"user": email, "ip": "203.0.113.5"}
    
    reasons := ip_whitelist.deny with input as inp
    count(reasons) == 0
}

# Test: High Strictness Org User (Non-Remote) should be denied from external IP
test_high_security_ip_deny if {
    # 1. Find a user in "acme_corp" (High Security: 10.x) who is NOT remote
    some email, user in data.users
    user.org_id == "acme_corp"
    # Ensure not in remote_workers which grants 0.0.0.0/0
    groups := object.get(user, "groups", [])
    not "remote_workers" in groups
    
    # 2. Test
    # External IP should fail (acme_corp allows 10.0.0.0/8)
    inp := {"user": email, "ip": "8.8.8.8"}
    
    reasons := ip_whitelist.deny with input as inp
    count(reasons) > 0
}
