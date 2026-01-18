# OPA/Rego Policy for OpenStack Keystone (Identity) Compliance
# Maps to CIS OpenStack Benchmark Section 1 controls

package openstack.keystone

import future.keywords.in

# Default deny
default allow = false

# =============================================================================
# CIS OpenStack 1.1: Keystone Configuration File Ownership
# =============================================================================

deny[msg] {
    input.file_checks.keystone_conf.owner != "root"
    
    msg := sprintf(
        "CIS-OS-1.1 CRITICAL: /etc/keystone/keystone.conf owner must be 'root'. Current: %s",
        [input.file_checks.keystone_conf.owner]
    )
}

deny[msg] {
    input.file_checks.keystone_conf.group != "keystone"
    
    msg := sprintf(
        "CIS-OS-1.1 CRITICAL: /etc/keystone/keystone.conf group must be 'keystone'. Current: %s",
        [input.file_checks.keystone_conf.group]
    )
}

# =============================================================================
# CIS OpenStack 1.2: Keystone Configuration File Permissions
# =============================================================================

deny[msg] {
    input.file_checks.keystone_conf.mode > 640
    
    msg := sprintf(
        "CIS-OS-1.2 CRITICAL: /etc/keystone/keystone.conf permissions must be 640 or stricter. Current: %d",
        [input.file_checks.keystone_conf.mode]
    )
}

# =============================================================================
# CIS OpenStack 1.3: Disable Insecure TLS Protocols
# =============================================================================

deny[msg] {
    tls_version := input.keystone_config.ssl.tls_version_min
    tls_version < "1.2"
    
    msg := sprintf(
        "CIS-OS-1.3 CRITICAL: Keystone TLS minimum version must be 1.2 or higher. Current: %s",
        [tls_version]
    )
}

# =============================================================================
# CIS OpenStack 1.4: Token Expiration
# =============================================================================

deny[msg] {
    expiration := input.keystone_config.token.expiration
    expiration > 3600
    
    msg := sprintf(
        "CIS-OS-1.4 HIGH: Token expiration should be 3600 seconds or less. Current: %d",
        [expiration]
    )
}

# =============================================================================
# CIS OpenStack 1.5: Disable Admin Token
# =============================================================================

deny[msg] {
    input.keystone_config.DEFAULT.admin_token != ""
    input.keystone_config.DEFAULT.admin_token != null
    
    msg := "CIS-OS-1.5 CRITICAL: Admin token must be disabled in production. Remove admin_token from keystone.conf"
}

# =============================================================================
# CIS OpenStack 1.6: Use Fernet Tokens
# =============================================================================

deny[msg] {
    provider := input.keystone_config.token.provider
    provider != "fernet"
    
    msg := sprintf(
        "CIS-OS-1.6 HIGH: Token provider should be 'fernet' for security. Current: %s",
        [provider]
    )
}

# =============================================================================
# CIS OpenStack 1.7: Password Strength Requirements
# =============================================================================

deny[msg] {
    min_length := input.keystone_config.security_compliance.password_regex_description
    min_length < 14
    
    msg := "CIS-OS-1.7 HIGH: Password minimum length should be 14 characters or more"
}

# =============================================================================
# CIS OpenStack 1.8: Lockout for Failed Attempts
# =============================================================================

deny[msg] {
    lockout := input.keystone_config.security_compliance.lockout_failure_attempts
    lockout > 5
    
    msg := sprintf(
        "CIS-OS-1.8 MEDIUM: Lockout should occur after 5 or fewer failed attempts. Current: %d",
        [lockout]
    )
}

deny[msg] {
    not input.keystone_config.security_compliance.lockout_failure_attempts
    
    msg := "CIS-OS-1.8 MEDIUM: Account lockout for failed attempts is not configured"
}

# =============================================================================
# CIS OpenStack 1.9: Secure Keystone API Endpoint
# =============================================================================

deny[msg] {
    endpoint := input.keystone_config.DEFAULT.public_endpoint
    not startswith(endpoint, "https://")
    
    msg := sprintf(
        "CIS-OS-1.9 CRITICAL: Keystone public endpoint must use HTTPS. Current: %s",
        [endpoint]
    )
}

# =============================================================================
# CIS OpenStack 1.10: Audit Logging Enabled
# =============================================================================

deny[msg] {
    input.keystone_config.audit.enabled != true
    
    msg := "CIS-OS-1.10 HIGH: Keystone audit logging must be enabled"
}

# =============================================================================
# Compliance Summary Helper
# =============================================================================

compliance_summary[control] {
    control := {
        "standard": "CIS OpenStack Foundations Benchmark v1.0",
        "section": "1. Identity (Keystone)",
        "controls_checked": ["1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.10"],
        "total_controls": 10
    }
}
