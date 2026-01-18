# OpenStack Security Policies (OPA/Rego)
# CIS OpenStack Foundations Benchmark

package openstack.security

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# ============================================
# Security Group Rules
# ============================================

# Deny security groups allowing SSH from anywhere (0.0.0.0/0)
deny_ssh_open_to_world contains msg if {
    input.resource_type == "OS::Neutron::SecurityGroup"
    some rule in input.properties.rules
    rule.protocol == "tcp"
    rule.port_range_min <= 22
    rule.port_range_max >= 22
    rule.remote_ip_prefix == "0.0.0.0/0"
    msg := sprintf("Security Group '%s' allows SSH (port 22) from 0.0.0.0/0", [input.properties.name])
}

# Deny security groups allowing RDP from anywhere
deny_rdp_open_to_world contains msg if {
    input.resource_type == "OS::Neutron::SecurityGroup"
    some rule in input.properties.rules
    rule.protocol == "tcp"
    rule.port_range_min <= 3389
    rule.port_range_max >= 3389
    rule.remote_ip_prefix == "0.0.0.0/0"
    msg := sprintf("Security Group '%s' allows RDP (port 3389) from 0.0.0.0/0", [input.properties.name])
}

# Deny overly permissive port ranges
deny_wide_port_range contains msg if {
    input.resource_type == "OS::Neutron::SecurityGroup"
    some rule in input.properties.rules
    port_range := rule.port_range_max - rule.port_range_min
    port_range > 100
    msg := sprintf("Security Group '%s' has overly permissive port range (%d ports)", [input.properties.name, port_range])
}

# ============================================
# Instance Metadata
# ============================================

# Require CIS compliance metadata on instances
deny_missing_compliance_metadata contains msg if {
    input.resource_type == "OS::Nova::Server"
    not input.properties.metadata.cis_compliant
    msg := sprintf("Instance '%s' missing required 'cis_compliant' metadata tag", [input.properties.name])
}

# ============================================
# Volume Encryption
# ============================================

# Warn if volume doesn't have encryption metadata
warn_unencrypted_volume contains msg if {
    input.resource_type == "OS::Cinder::Volume"
    not input.properties.metadata.encrypted
    msg := sprintf("Volume '%s' may not be encrypted - add 'encrypted: true' metadata", [input.properties.name])
}

# ============================================
# Network Configuration
# ============================================

# Deny instances attached directly to external networks
deny_external_network_attachment contains msg if {
    input.resource_type == "OS::Nova::Server"
    some network in input.properties.networks
    contains(lower(network.network), "external")
    msg := sprintf("Instance '%s' should not be directly attached to external network", [input.properties.name])
}

# Deny instances attached directly to public networks
deny_public_network_attachment contains msg if {
    input.resource_type == "OS::Nova::Server"
    some network in input.properties.networks
    contains(lower(network.network), "public")
    msg := sprintf("Instance '%s' should not be directly attached to public network", [input.properties.name])
}

# ============================================
# User Data Security
# ============================================

# Warn if user_data contains potential secrets
warn_secrets_in_userdata contains msg if {
    input.resource_type == "OS::Nova::Server"
    user_data := input.properties.user_data
    contains(lower(user_data), "password")
    msg := sprintf("Instance '%s' user_data may contain hardcoded passwords", [input.properties.name])
}

warn_secrets_in_userdata contains msg if {
    input.resource_type == "OS::Nova::Server"
    user_data := input.properties.user_data
    contains(lower(user_data), "secret_key")
    msg := sprintf("Instance '%s' user_data may contain hardcoded secret keys", [input.properties.name])
}

# ============================================
# Floating IP Restrictions
# ============================================

# Warn about floating IP assignments (should be intentional)
warn_floating_ip contains msg if {
    input.resource_type == "OS::Neutron::FloatingIPAssociation"
    msg := "FloatingIP assignment detected - ensure this is intentional and instance is properly secured"
}

# ============================================
# Main Policy Results
# ============================================

# Collect all violations
violations := deny_ssh_open_to_world | deny_rdp_open_to_world | deny_wide_port_range | deny_missing_compliance_metadata | deny_external_network_attachment | deny_public_network_attachment

# Collect all warnings
warnings := warn_unencrypted_volume | warn_secrets_in_userdata | warn_floating_ip

# Final decision
allow if {
    count(violations) == 0
}

deny if {
    count(violations) > 0
}
