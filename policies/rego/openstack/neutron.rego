# OPA/Rego Policy for OpenStack Neutron (Networking) Compliance
# Maps to CIS OpenStack Benchmark Section 3 controls

package openstack.neutron

import future.keywords.in

# Default deny
default allow = false

# =============================================================================
# CIS OpenStack 3.1: Neutron Configuration File Ownership
# =============================================================================

deny[msg] {
    input.file_checks.neutron_conf.owner != "root"
    
    msg := sprintf(
        "CIS-OS-3.1 CRITICAL: /etc/neutron/neutron.conf owner must be 'root'. Current: %s",
        [input.file_checks.neutron_conf.owner]
    )
}

deny[msg] {
    input.file_checks.neutron_conf.group != "neutron"
    
    msg := sprintf(
        "CIS-OS-3.1 CRITICAL: /etc/neutron/neutron.conf group must be 'neutron'. Current: %s",
        [input.file_checks.neutron_conf.group]
    )
}

# =============================================================================
# CIS OpenStack 3.2: Neutron Configuration File Permissions
# =============================================================================

deny[msg] {
    input.file_checks.neutron_conf.mode > 640
    
    msg := sprintf(
        "CIS-OS-3.2 CRITICAL: /etc/neutron/neutron.conf permissions must be 640 or stricter. Current: %d",
        [input.file_checks.neutron_conf.mode]
    )
}

# =============================================================================
# CIS OpenStack 3.3: Neutron API Uses SSL
# =============================================================================

deny[msg] {
    input.neutron_config.ssl.use_ssl != true
    
    msg := "CIS-OS-3.3 CRITICAL: Neutron API must use SSL. Set [ssl] use_ssl = true"
}

# =============================================================================
# CIS OpenStack 3.4: Authentication Strategy is Keystone
# =============================================================================

deny[msg] {
    strategy := input.neutron_config.DEFAULT.auth_strategy
    strategy != "keystone"
    
    msg := sprintf(
        "CIS-OS-3.4 CRITICAL: Neutron auth_strategy must be 'keystone'. Current: %s",
        [strategy]
    )
}

# =============================================================================
# CIS OpenStack 3.5: Secure RPC Communication
# =============================================================================

deny[msg] {
    transport := input.neutron_config.DEFAULT.transport_url
    startswith(transport, "rabbit://")
    not contains(transport, "ssl=true")
    
    msg := "CIS-OS-3.5 HIGH: RabbitMQ transport should use SSL encryption"
}

# =============================================================================
# CIS OpenStack 3.6: Security Group Driver
# =============================================================================

deny[msg] {
    not input.neutron_config.securitygroup.firewall_driver
    
    msg := "CIS-OS-3.6 HIGH: Security group firewall_driver must be configured"
}

warn[msg] {
    driver := input.neutron_config.securitygroup.firewall_driver
    driver == "neutron.agent.firewall.NoopFirewallDriver"
    
    msg := "CIS-OS-3.6 HIGH: NoopFirewallDriver disables security groups - ensure this is intentional"
}

# =============================================================================
# CIS OpenStack 3.7: Network Isolation (VXLAN/GRE)
# =============================================================================

warn[msg] {
    type_drivers := input.neutron_config.ml2.type_drivers
    contains(type_drivers, "flat")
    not contains(type_drivers, "vxlan")
    not contains(type_drivers, "gre")
    
    msg := "CIS-OS-3.7 MEDIUM: Consider using VXLAN or GRE for better network isolation"
}

# =============================================================================
# CIS OpenStack 3.8: Limit Port Security
# =============================================================================

deny[msg] {
    input.neutron_config.DEFAULT.allow_overlapping_ips != true
    
    msg := "CIS-OS-3.8 MEDIUM: allow_overlapping_ips should be true for proper tenant isolation"
}

# =============================================================================
# Compliance Summary Helper
# =============================================================================

compliance_summary[control] {
    control := {
        "standard": "CIS OpenStack Foundations Benchmark v1.0",
        "section": "3. Networking (Neutron)",
        "controls_checked": ["3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8"],
        "total_controls": 8
    }
}
