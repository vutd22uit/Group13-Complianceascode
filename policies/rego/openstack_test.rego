# OpenStack Security Policies - Unit Tests
# Run with: opa test policies/rego/ -v

package openstack.security_test

import data.openstack.security

# ============================================
# Test: SSH Open to World
# ============================================

test_deny_ssh_open_to_world {
    result := security.deny_ssh_open_to_world with input as {
        "resource_type": "OS::Neutron::SecurityGroup",
        "properties": {
            "name": "insecure-sg",
            "rules": [
                {
                    "protocol": "tcp",
                    "port_range_min": 22,
                    "port_range_max": 22,
                    "remote_ip_prefix": "0.0.0.0/0"
                }
            ]
        }
    }
    count(result) > 0
}

test_allow_ssh_from_private_ip {
    result := security.deny_ssh_open_to_world with input as {
        "resource_type": "OS::Neutron::SecurityGroup",
        "properties": {
            "name": "secure-sg",
            "rules": [
                {
                    "protocol": "tcp",
                    "port_range_min": 22,
                    "port_range_max": 22,
                    "remote_ip_prefix": "10.0.0.0/8"
                }
            ]
        }
    }
    count(result) == 0
}

# ============================================
# Test: RDP Open to World
# ============================================

test_deny_rdp_open_to_world {
    result := security.deny_rdp_open_to_world with input as {
        "resource_type": "OS::Neutron::SecurityGroup",
        "properties": {
            "name": "windows-sg",
            "rules": [
                {
                    "protocol": "tcp",
                    "port_range_min": 3389,
                    "port_range_max": 3389,
                    "remote_ip_prefix": "0.0.0.0/0"
                }
            ]
        }
    }
    count(result) > 0
}

# ============================================
# Test: Wide Port Range
# ============================================

test_deny_wide_port_range {
    result := security.deny_wide_port_range with input as {
        "resource_type": "OS::Neutron::SecurityGroup",
        "properties": {
            "name": "permissive-sg",
            "rules": [
                {
                    "protocol": "tcp",
                    "port_range_min": 1,
                    "port_range_max": 1000,
                    "remote_ip_prefix": "10.0.0.0/8"
                }
            ]
        }
    }
    count(result) > 0
}

test_allow_narrow_port_range {
    result := security.deny_wide_port_range with input as {
        "resource_type": "OS::Neutron::SecurityGroup",
        "properties": {
            "name": "web-sg",
            "rules": [
                {
                    "protocol": "tcp",
                    "port_range_min": 80,
                    "port_range_max": 90,
                    "remote_ip_prefix": "10.0.0.0/8"
                }
            ]
        }
    }
    count(result) == 0
}

# ============================================
# Test: Missing Compliance Metadata
# ============================================

test_deny_missing_compliance_metadata {
    result := security.deny_missing_compliance_metadata with input as {
        "resource_type": "OS::Nova::Server",
        "properties": {
            "name": "untagged-instance",
            "metadata": {}
        }
    }
    count(result) > 0
}

test_allow_compliant_instance {
    result := security.deny_missing_compliance_metadata with input as {
        "resource_type": "OS::Nova::Server",
        "properties": {
            "name": "compliant-instance",
            "metadata": {
                "cis_compliant": "true"
            }
        }
    }
    count(result) == 0
}

# ============================================
# Test: External Network Attachment
# ============================================

test_deny_external_network_attachment {
    result := security.deny_external_network_attachment with input as {
        "resource_type": "OS::Nova::Server",
        "properties": {
            "name": "exposed-instance",
            "networks": [
                {"network": "external-net"}
            ]
        }
    }
    count(result) > 0
}

test_allow_internal_network {
    result := security.deny_external_network_attachment with input as {
        "resource_type": "OS::Nova::Server",
        "properties": {
            "name": "internal-instance",
            "networks": [
                {"network": "internal-net"}
            ]
        }
    }
    count(result) == 0
}

# ============================================
# Test: Secrets in Userdata
# ============================================

test_warn_password_in_userdata {
    result := security.warn_secrets_in_userdata with input as {
        "resource_type": "OS::Nova::Server",
        "properties": {
            "name": "bad-instance",
            "user_data": "#!/bin/bash\nDB_PASSWORD=secret123"
        }
    }
    count(result) > 0
}

test_allow_safe_userdata {
    result := security.warn_secrets_in_userdata with input as {
        "resource_type": "OS::Nova::Server",
        "properties": {
            "name": "safe-instance",
            "user_data": "#!/bin/bash\napt update && apt install -y nginx"
        }
    }
    count(result) == 0
}

# ============================================
# Test: Unencrypted Volume Warning
# ============================================

test_warn_unencrypted_volume {
    result := security.warn_unencrypted_volume with input as {
        "resource_type": "OS::Cinder::Volume",
        "properties": {
            "name": "unencrypted-vol",
            "size": 100,
            "metadata": {}
        }
    }
    count(result) > 0
}

test_allow_encrypted_volume {
    result := security.warn_unencrypted_volume with input as {
        "resource_type": "OS::Cinder::Volume",
        "properties": {
            "name": "encrypted-vol",
            "size": 100,
            "metadata": {
                "encrypted": "true"
            }
        }
    }
    count(result) == 0
}

# ============================================
# Test: Overall Policy Decision
# ============================================

test_deny_policy_with_violations {
    security.deny with input as {
        "resource_type": "OS::Neutron::SecurityGroup",
        "properties": {
            "name": "bad-sg",
            "rules": [
                {
                    "protocol": "tcp",
                    "port_range_min": 22,
                    "port_range_max": 22,
                    "remote_ip_prefix": "0.0.0.0/0"
                }
            ]
        }
    }
}

test_allow_policy_no_violations {
    security.allow with input as {
        "resource_type": "OS::Neutron::SecurityGroup",
        "properties": {
            "name": "good-sg",
            "rules": [
                {
                    "protocol": "tcp",
                    "port_range_min": 443,
                    "port_range_max": 443,
                    "remote_ip_prefix": "10.0.0.0/8"
                }
            ]
        }
    }
}
