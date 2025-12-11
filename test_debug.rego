package policies.test.debug

import future.keywords.if
import future.keywords.in
import data.policies.common.inheritance

test_assert_config_loaded if {
    inp := {"user": "alice@acme.com"}
    c := inheritance.get_effective_config("security") with input as inp
    c.password_min_length == 12
    c.password_reject_common == true
}

test_assert_reasons_correct if {
    inp := {"user": "alice@acme.com", "password": "admin"}
    r := data.policies.security.password.deny with input as inp
    r["Password is too common/vulnerable"]
}
