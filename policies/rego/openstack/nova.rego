# OPA/Rego Policy for OpenStack Nova (Compute) Compliance
# Maps to CIS OpenStack Benchmark Section 2 controls

package openstack.nova

import future.keywords.in

# Default deny
default allow = false

# =============================================================================
# CIS OpenStack 2.1: Nova Configuration File Ownership
# =============================================================================

deny[msg] {
    input.file_checks.nova_conf.owner != "root"
    
    msg := sprintf(
        "CIS-OS-2.1 CRITICAL: /etc/nova/nova.conf owner must be 'root'. Current: %s",
        [input.file_checks.nova_conf.owner]
    )
}

deny[msg] {
    input.file_checks.nova_conf.group != "nova"
    
    msg := sprintf(
        "CIS-OS-2.1 CRITICAL: /etc/nova/nova.conf group must be 'nova'. Current: %s",
        [input.file_checks.nova_conf.group]
    )
}

# =============================================================================
# CIS OpenStack 2.2: Nova Configuration File Permissions
# =============================================================================

deny[msg] {
    input.file_checks.nova_conf.mode > 640
    
    msg := sprintf(
        "CIS-OS-2.2 CRITICAL: /etc/nova/nova.conf permissions must be 640 or stricter. Current: %d",
        [input.file_checks.nova_conf.mode]
    )
}

# =============================================================================
# CIS OpenStack 2.3: VNC Must Use SSL
# =============================================================================

deny[msg] {
    input.nova_config.vnc.enabled == true
    not input.nova_config.vnc.novncproxy_base_url
    
    msg := "CIS-OS-2.3 HIGH: VNC is enabled but novncproxy_base_url is not configured"
}

deny[msg] {
    input.nova_config.vnc.enabled == true
    url := input.nova_config.vnc.novncproxy_base_url
    not startswith(url, "https://")
    
    msg := sprintf(
        "CIS-OS-2.3 HIGH: VNC proxy must use HTTPS. Current URL: %s",
        [url]
    )
}

deny[msg] {
    input.nova_config.vnc.novncproxy_host == "0.0.0.0"
    
    msg := "CIS-OS-2.3 HIGH: VNC proxy should not bind to 0.0.0.0 (all interfaces)"
}

# =============================================================================
# CIS OpenStack 2.4: Internal API Uses HTTPS
# =============================================================================

deny[msg] {
    glance_url := input.nova_config.glance.api_servers
    not startswith(glance_url, "https://")
    
    msg := sprintf(
        "CIS-OS-2.4 CRITICAL: Glance API endpoint must use HTTPS. Current: %s",
        [glance_url]
    )
}

deny[msg] {
    neutron_url := input.nova_config.neutron.auth_url
    not startswith(neutron_url, "https://")
    
    msg := sprintf(
        "CIS-OS-2.4 CRITICAL: Neutron auth URL must use HTTPS. Current: %s",
        [neutron_url]
    )
}

deny[msg] {
    keystone_url := input.nova_config.keystone_authtoken.auth_url
    not startswith(keystone_url, "https://")
    
    msg := sprintf(
        "CIS-OS-2.4 CRITICAL: Keystone auth URL must use HTTPS. Current: %s",
        [keystone_url]
    )
}

# =============================================================================
# CIS OpenStack 2.5: Disable Metadata Service When Not Needed
# =============================================================================

warn[msg] {
    input.nova_config.DEFAULT.enabled_apis
    contains(input.nova_config.DEFAULT.enabled_apis, "metadata")
    
    msg := "CIS-OS-2.5 MEDIUM: Metadata API is enabled. Ensure it is required for your deployment."
}

# =============================================================================
# CIS OpenStack 2.6: Secure Serial Console
# =============================================================================

deny[msg] {
    input.nova_config.serial_console.enabled == true
    not input.nova_config.serial_console.proxyclient_address
    
    msg := "CIS-OS-2.6 HIGH: Serial console is enabled but proxyclient_address is not configured"
}

# =============================================================================
# CIS OpenStack 2.7: Hypervisor Disk Encryption
# =============================================================================

warn[msg] {
    input.nova_config.libvirt.images_type == "raw"
    not input.nova_config.ephemeral_storage_encryption.enabled
    
    msg := "CIS-OS-2.7 HIGH: Consider enabling ephemeral storage encryption for enhanced data protection"
}

# =============================================================================
# CIS OpenStack 2.8: Disable Password Authentication for VNC
# =============================================================================

deny[msg] {
    input.nova_config.vnc.enabled == true
    input.nova_config.vnc.auth_schemes == null
    
    msg := "CIS-OS-2.8 HIGH: VNC authentication scheme must be configured when VNC is enabled"
}

# =============================================================================
# CIS OpenStack 2.9: Secure Live Migration
# =============================================================================

deny[msg] {
    input.nova_config.libvirt.live_migration_tunnelled != true
    input.nova_config.libvirt.live_migration_with_native_tls != true
    
    msg := "CIS-OS-2.9 HIGH: Live migration must use TLS tunneling for security"
}

# =============================================================================
# CIS OpenStack 2.10: Limit CPU/Memory Overcommitment
# =============================================================================

warn[msg] {
    ratio := input.nova_config.DEFAULT.cpu_allocation_ratio
    ratio > 16
    
    msg := sprintf(
        "CIS-OS-2.10 LOW: CPU overcommitment ratio is high (%d). Consider reducing for stability.",
        [ratio]
    )
}

warn[msg] {
    ratio := input.nova_config.DEFAULT.ram_allocation_ratio
    ratio > 1.5
    
    msg := sprintf(
        "CIS-OS-2.10 LOW: RAM overcommitment ratio is high (%f). Consider reducing for stability.",
        [ratio]
    )
}

# =============================================================================
# CIS OpenStack 2.11: Block Device Mapping
# =============================================================================

deny[msg] {
    input.nova_config.DEFAULT.block_device_allocate_retries < 60
    
    msg := "CIS-OS-2.11 MEDIUM: block_device_allocate_retries should be at least 60"
}

# =============================================================================
# CIS OpenStack 2.12: Secure Compute API
# =============================================================================

deny[msg] {
    api_listen := input.nova_config.DEFAULT.osapi_compute_listen
    api_listen == "0.0.0.0"
    
    msg := "CIS-OS-2.12 HIGH: Nova API should not listen on all interfaces (0.0.0.0)"
}

# =============================================================================
# Compliance Summary Helper
# =============================================================================

compliance_summary[control] {
    control := {
        "standard": "CIS OpenStack Foundations Benchmark v1.0",
        "section": "2. Compute (Nova)",
        "controls_checked": ["2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11", "2.12"],
        "total_controls": 12
    }
}
