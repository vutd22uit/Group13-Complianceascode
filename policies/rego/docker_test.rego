package docker.cis

# ============================================================
# OPA Tests for CIS Docker Benchmark Policies
# ============================================================

# ============================================================
# Test Section 4: Container Images
# ============================================================

test_deny_root_user_empty {
  deny_root_user["CIS 4.1: Container '/test' runs as root user. Set a non-root USER in the Dockerfile."] with input as {
    "containers": [{"Name": "/test", "Config": {"User": ""}}]
  }
}

test_deny_root_user_named_root {
  deny_root_user["CIS 4.1: Container '/test' runs as root user. Set a non-root USER in the Dockerfile."] with input as {
    "containers": [{"Name": "/test", "Config": {"User": "root"}}]
  }
}

test_deny_root_user_uid_zero {
  deny_root_user["CIS 4.1: Container '/test' runs as root user. Set a non-root USER in the Dockerfile."] with input as {
    "containers": [{"Name": "/test", "Config": {"User": "0"}}]
  }
}

test_allow_non_root_user {
  not deny_root_user[_] with input as {
    "containers": [{"Name": "/test", "Config": {"User": "1000"}}]
  }
}

test_deny_no_healthcheck_missing {
  deny_no_healthcheck["CIS 4.6: Container '/test' has no HEALTHCHECK configured."] with input as {
    "containers": [{"Name": "/test", "Config": {}}]
  }
}

# ============================================================
# Test Section 5: Container Runtime
# ============================================================

test_deny_privileged_container {
  deny_privileged["CIS 5.4 [CRITICAL]: Container '/test' is running in privileged mode. This must be disabled."] with input as {
    "containers": [{"Name": "/test", "HostConfig": {"Privileged": true}}]
  }
}

test_allow_non_privileged_container {
  not deny_privileged[_] with input as {
    "containers": [{"Name": "/test", "HostConfig": {"Privileged": false}}]
  }
}

test_deny_host_network {
  deny_host_network["CIS 5.9 [CRITICAL]: Container '/test' shares the host network namespace (--net=host)."] with input as {
    "containers": [{"Name": "/test", "HostConfig": {"NetworkMode": "host"}}]
  }
}

test_allow_bridge_network {
  not deny_host_network[_] with input as {
    "containers": [{"Name": "/test", "HostConfig": {"NetworkMode": "bridge"}}]
  }
}

test_deny_no_memory_limit {
  deny_no_memory_limit["CIS 5.10: Container '/test' has no memory limit. Set --memory to prevent resource exhaustion."] with input as {
    "containers": [{"Name": "/test", "HostConfig": {"Memory": 0}}]
  }
}

test_allow_memory_limit {
  not deny_no_memory_limit[_] with input as {
    "containers": [{"Name": "/test", "HostConfig": {"Memory": 536870912}}]
  }
}

test_deny_writable_root {
  deny_writable_root["CIS 5.12: Container '/test' has a writable root filesystem. Use --read-only flag."] with input as {
    "containers": [{"Name": "/test", "HostConfig": {"ReadonlyRootfs": false}}]
  }
}

test_allow_readonly_root {
  not deny_writable_root[_] with input as {
    "containers": [{"Name": "/test", "HostConfig": {"ReadonlyRootfs": true}}]
  }
}

test_deny_host_pid {
  deny_host_pid["CIS 5.15 [CRITICAL]: Container '/test' shares the host PID namespace (--pid=host)."] with input as {
    "containers": [{"Name": "/test", "HostConfig": {"PidMode": "host"}}]
  }
}

test_deny_host_ipc {
  deny_host_ipc["CIS 5.16 [CRITICAL]: Container '/test' shares the host IPC namespace (--ipc=host)."] with input as {
    "containers": [{"Name": "/test", "HostConfig": {"IpcMode": "host"}}]
  }
}

test_deny_seccomp_unconfined {
  deny_seccomp_unconfined["CIS 5.21: Container '/test' has seccomp disabled (seccomp=unconfined)."] with input as {
    "containers": [{"Name": "/test", "HostConfig": {"SecurityOpt": ["seccomp=unconfined"]}}]
  }
}

test_deny_no_new_privileges_missing {
  deny_new_privileges["CIS 5.25 [CRITICAL]: Container '/test' does not have 'no-new-privileges' set."] with input as {
    "containers": [{"Name": "/test", "HostConfig": {"SecurityOpt": []}}]
  }
}

test_allow_no_new_privileges_set {
  not deny_new_privileges[_] with input as {
    "containers": [{"Name": "/test", "HostConfig": {"SecurityOpt": ["no-new-privileges:true"]}}]
  }
}

test_deny_sensitive_mount_root {
  deny_sensitive_mount["CIS 5.5 [CRITICAL]: Container '/test' mounts sensitive host path '/'."] with input as {
    "containers": [{"Name": "/test", "Mounts": [{"Source": "/", "Destination": "/mnt"}]}]
  }
}

test_allow_non_sensitive_mount {
  not deny_sensitive_mount[_] with input as {
    "containers": [{"Name": "/test", "Mounts": [{"Source": "/data/app", "Destination": "/app"}]}]
  }
}

# ============================================================
# Test Section 2: Daemon Configuration
# ============================================================

test_deny_insecure_registry {
  deny_insecure_registry["CIS 2.5 [CRITICAL]: Insecure registries are configured. Remove 'insecure-registries' from daemon.json."] with input as {
    "daemon_config": {"insecure-registries": ["10.0.0.1:5000"]}
  }
}

test_allow_no_insecure_registry {
  not deny_insecure_registry[_] with input as {
    "daemon_config": {"insecure-registries": []}
  }
}

test_deny_experimental_features {
  deny_experimental["CIS 2.18: Experimental features are enabled in Docker daemon. Disable in production."] with input as {
    "daemon_config": {"experimental": true}
  }
}

test_allow_no_experimental {
  not deny_experimental[_] with input as {
    "daemon_config": {"experimental": false}
  }
}

# ============================================================
# Test: Overall compliance
# ============================================================

test_compliant_with_no_violations {
  compliant with input as {
    "containers": [],
    "daemon_config": {
      "icc": false,
      "insecure-registries": [],
      "no-new-privileges": true,
      "live-restore": true,
      "experimental": false
    }
  }
}
