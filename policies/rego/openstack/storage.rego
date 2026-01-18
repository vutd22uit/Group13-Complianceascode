# OPA/Rego Policy for OpenStack Cinder/Swift (Storage) Compliance
# Maps to CIS OpenStack Benchmark Section 4 controls

package openstack.storage

import future.keywords.in

# Default deny
default allow = false

# =============================================================================
# CIS OpenStack 4.1: Cinder Configuration File Ownership
# =============================================================================

deny[msg] {
    input.file_checks.cinder_conf.owner != "root"
    
    msg := sprintf(
        "CIS-OS-4.1 CRITICAL: /etc/cinder/cinder.conf owner must be 'root'. Current: %s",
        [input.file_checks.cinder_conf.owner]
    )
}

deny[msg] {
    input.file_checks.cinder_conf.group != "cinder"
    
    msg := sprintf(
        "CIS-OS-4.1 CRITICAL: /etc/cinder/cinder.conf group must be 'cinder'. Current: %s",
        [input.file_checks.cinder_conf.group]
    )
}

# =============================================================================
# CIS OpenStack 4.2: Cinder Configuration File Permissions
# =============================================================================

deny[msg] {
    input.file_checks.cinder_conf.mode > 640
    
    msg := sprintf(
        "CIS-OS-4.2 CRITICAL: /etc/cinder/cinder.conf permissions must be 640 or stricter. Current: %d",
        [input.file_checks.cinder_conf.mode]
    )
}

# =============================================================================
# CIS OpenStack 4.3: NAS Secure File Permissions
# =============================================================================

warn[msg] {
    input.cinder_config.DEFAULT.nas_secure_file_permissions != "auto"
    input.cinder_config.DEFAULT.nas_secure_file_permissions != true
    
    msg := "CIS-OS-4.3 HIGH: nas_secure_file_permissions should be set to 'auto' or true"
}

warn[msg] {
    input.cinder_config.DEFAULT.nas_secure_file_operations != "auto"
    input.cinder_config.DEFAULT.nas_secure_file_operations != true
    
    msg := "CIS-OS-4.3 HIGH: nas_secure_file_operations should be set to 'auto' or true"
}

# =============================================================================
# CIS OpenStack 4.4: Swift Hash Path Configuration
# =============================================================================

deny[msg] {
    prefix := input.swift_config["swift-hash"].swift_hash_path_prefix
    prefix == "changeme"
    
    msg := "CIS-OS-4.4 CRITICAL: swift_hash_path_prefix must be changed from default 'changeme'"
}

deny[msg] {
    suffix := input.swift_config["swift-hash"].swift_hash_path_suffix
    suffix == "changeme"
    
    msg := "CIS-OS-4.4 CRITICAL: swift_hash_path_suffix must be changed from default 'changeme'"
}

deny[msg] {
    not input.swift_config["swift-hash"].swift_hash_path_prefix
    
    msg := "CIS-OS-4.4 CRITICAL: swift_hash_path_prefix must be configured"
}

deny[msg] {
    not input.swift_config["swift-hash"].swift_hash_path_suffix
    
    msg := "CIS-OS-4.4 CRITICAL: swift_hash_path_suffix must be configured"
}

# =============================================================================
# CIS OpenStack 4.5: Cinder API Uses HTTPS
# =============================================================================

deny[msg] {
    endpoint := input.cinder_config.DEFAULT.osapi_volume_base_URL
    endpoint != null
    not startswith(endpoint, "https://")
    
    msg := sprintf(
        "CIS-OS-4.5 CRITICAL: Cinder API endpoint must use HTTPS. Current: %s",
        [endpoint]
    )
}

# =============================================================================
# CIS OpenStack 4.6: Volume Encryption Support
# =============================================================================

warn[msg] {
    not input.cinder_config.key_manager.backend
    
    msg := "CIS-OS-4.6 HIGH: Volume encryption key manager should be configured for sensitive data"
}

deny[msg] {
    backend := input.cinder_config.key_manager.backend
    backend == "cinder.keymgr.conf_key_mgr.ConfKeyManager"
    
    msg := "CIS-OS-4.6 HIGH: ConfKeyManager is not recommended for production. Use Barbican."
}

# =============================================================================
# Swift-specific Controls
# =============================================================================

# CIS OpenStack 4.7: Swift Proxy Configuration
deny[msg] {
    input.file_checks.swift_proxy_conf.owner != "root"
    
    msg := sprintf(
        "CIS-OS-4.7 CRITICAL: /etc/swift/proxy-server.conf owner must be 'root'. Current: %s",
        [input.file_checks.swift_proxy_conf.owner]
    )
}

deny[msg] {
    input.file_checks.swift_proxy_conf.mode > 640
    
    msg := sprintf(
        "CIS-OS-4.7 CRITICAL: /etc/swift/proxy-server.conf permissions must be 640 or stricter. Current: %d",
        [input.file_checks.swift_proxy_conf.mode]
    )
}

# CIS OpenStack 4.8: Swift TempAuth Disabled
deny[msg] {
    pipeline := input.swift_proxy_config.pipeline.main
    contains(pipeline, "tempauth")
    
    msg := "CIS-OS-4.8 HIGH: TempAuth should be disabled in production. Use Keystone authentication."
}

# =============================================================================
# Compliance Summary Helper
# =============================================================================

compliance_summary[control] {
    control := {
        "standard": "CIS OpenStack Foundations Benchmark v1.0",
        "section": "4. Storage (Cinder/Swift)",
        "controls_checked": ["4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8"],
        "total_controls": 8
    }
}
