package policies.security.password

import future.keywords.if
import future.keywords.in
import data.policies.common.inheritance

# Helper: Check if string contains substring (case insensitive?) - Keeping it simple for now
contains_string(str, substr) if {
    contains(lower(str), lower(substr))
}

# 1. Length Check
deny[reason] if {
    config := inheritance.get_effective_config("security")
    min_len := object.get(config, "password_min_length", 8)
    count(input.password) < min_len
    reason := sprintf("Password must be at least %d characters long", [min_len])
}

# 2. Number Check
deny[reason] if {
    config := inheritance.get_effective_config("security")
    object.get(config, "password_require_number", false) == true
    not regex.match("[0-9]", input.password)
    reason := "Password must contain at least one number"
}

# 3. Special Char Check
deny[reason] if {
    config := inheritance.get_effective_config("security")
    object.get(config, "password_require_special_char", false) == true
    not regex.match("[!@#$%^&*(){}<>?]", input.password)
    reason := "Password must contain at least one special character"
}

# 4. Uppercase Check (New)
deny[reason] if {
    config := inheritance.get_effective_config("security")
    object.get(config, "password_require_uppercase", false) == true
    not regex.match("[A-Z]", input.password)
    reason := "Password must contain at least one uppercase letter"
}

# 5. Lowercase Check (New)
deny[reason] if {
    config := inheritance.get_effective_config("security")
    object.get(config, "password_require_lowercase", false) == true
    not regex.match("[a-z]", input.password)
    reason := "Password must contain at least one lowercase letter"
}

# 6. User Info Check (New) - Prevent username/email parts in password
deny[reason] if {
    config := inheritance.get_effective_config("security")
    object.get(config, "password_reject_user_info", false) == true
    
    # Parse email to get username part
    parts := split(input.user, "@")
    username := parts[0]
    
    contains_string(input.password, username)
    
    reason := "Password must not contain your username or email address"
}
