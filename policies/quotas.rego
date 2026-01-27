package mail_service.quotas

default allow = false
default warn = []

# Deny new usage if quota exceeded
allow {
    not quota_exceeded
}

quota_exceeded {
    org_id := input.org_id
    user_id := input.user
    
    # Securely fetch quota from Data Store
    user := data.organizations[org_id].users[user_id]
    
    usage := parse_size(input.storage_used)
    limit := parse_size(user.storage_quota)
    
    usage >= limit
}

# Helper to parse sizes (simplified)
parse_size(s) = n {
    endswith(s, "GB")
    n := to_number(substring(s, 0, count(s)-2)) * 1024 * 1024 * 1024
} else = n {
    endswith(s, "MB")
    n := to_number(substring(s, 0, count(s)-2)) * 1024 * 1024
} else = 0 {
    # Default fallback
    n := 0
}
