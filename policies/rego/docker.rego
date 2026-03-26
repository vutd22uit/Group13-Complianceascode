package docker.cis

# ============================================================
# CIS Docker Benchmark v1.6.0 - OPA/Rego Policy Definitions
# ============================================================
# These policies evaluate Docker container and daemon configurations
# for compliance with the CIS Docker Benchmark.
#
# Input format expected:
# {
#   "containers": [ <docker inspect output per container> ],
#   "daemon_config": { <daemon.json content> },
#   "images": [ <docker image inspect output> ]
# }
# ============================================================

# ============================================================
# Section 4: Container Images
# ============================================================

# CIS 4.1: Container must run as non-root user
deny_root_user[msg] {
  container := input.containers[_]
  user := container.Config.User
  user_is_root(user)
  msg := sprintf("CIS 4.1: Container '%s' runs as root user. Set a non-root USER in the Dockerfile.", [container.Name])
}

user_is_root(user) {
  user == ""
}

user_is_root(user) {
  user == "root"
}

user_is_root(user) {
  user == "0"
}

user_is_root(user) {
  startswith(user, "0:")
}

# CIS 4.5: Docker Content Trust must be enabled
warn_content_trust[msg] {
  not input.daemon_config.content_trust
  msg := "CIS 4.5: Docker Content Trust is not enabled. Set DOCKER_CONTENT_TRUST=1."
}

# CIS 4.6: Container image must have HEALTHCHECK
deny_no_healthcheck[msg] {
  container := input.containers[_]
  not container.Config.Healthcheck
  msg := sprintf("CIS 4.6: Container '%s' has no HEALTHCHECK configured.", [container.Name])
}

deny_no_healthcheck[msg] {
  container := input.containers[_]
  container.Config.Healthcheck == {}
  msg := sprintf("CIS 4.6: Container '%s' has an empty HEALTHCHECK configuration.", [container.Name])
}

# ============================================================
# Section 5: Container Runtime
# ============================================================

# CIS 5.4: Privileged containers are not allowed
deny_privileged[msg] {
  container := input.containers[_]
  container.HostConfig.Privileged == true
  msg := sprintf("CIS 5.4 [CRITICAL]: Container '%s' is running in privileged mode. This must be disabled.", [container.Name])
}

# CIS 5.5: Sensitive host directories must not be mounted
deny_sensitive_mount[msg] {
  container := input.containers[_]
  mount := container.Mounts[_]
  sensitive_path(mount.Source)
  msg := sprintf("CIS 5.5 [CRITICAL]: Container '%s' mounts sensitive host path '%s'.", [container.Name, mount.Source])
}

sensitive_path(path) {
  sensitive_dirs := ["/", "/boot", "/dev", "/etc", "/lib", "/proc", "/sys", "/usr"]
  path == sensitive_dirs[_]
}

# CIS 5.9: Host network namespace must not be shared
deny_host_network[msg] {
  container := input.containers[_]
  container.HostConfig.NetworkMode == "host"
  msg := sprintf("CIS 5.9 [CRITICAL]: Container '%s' shares the host network namespace (--net=host).", [container.Name])
}

# CIS 5.10: Memory limit must be set
deny_no_memory_limit[msg] {
  container := input.containers[_]
  container.HostConfig.Memory == 0
  msg := sprintf("CIS 5.10: Container '%s' has no memory limit. Set --memory to prevent resource exhaustion.", [container.Name])
}

# CIS 5.11: CPU shares must be set
deny_no_cpu_limit[msg] {
  container := input.containers[_]
  container.HostConfig.CpuShares == 0
  msg := sprintf("CIS 5.11: Container '%s' has no CPU shares set. Set --cpu-shares for fair scheduling.", [container.Name])
}

# CIS 5.12: Root filesystem must be read-only
deny_writable_root[msg] {
  container := input.containers[_]
  container.HostConfig.ReadonlyRootfs == false
  msg := sprintf("CIS 5.12: Container '%s' has a writable root filesystem. Use --read-only flag.", [container.Name])
}

# CIS 5.14: Restart policy must be on-failure with max 5 retries
deny_restart_policy[msg] {
  container := input.containers[_]
  container.HostConfig.RestartPolicy.Name == "always"
  msg := sprintf("CIS 5.14: Container '%s' uses 'always' restart policy. Use 'on-failure:5' instead.", [container.Name])
}

deny_restart_policy[msg] {
  container := input.containers[_]
  container.HostConfig.RestartPolicy.Name == "unless-stopped"
  msg := sprintf("CIS 5.14: Container '%s' uses 'unless-stopped' restart policy. Use 'on-failure:5' instead.", [container.Name])
}

deny_restart_policy[msg] {
  container := input.containers[_]
  container.HostConfig.RestartPolicy.Name == "on-failure"
  container.HostConfig.RestartPolicy.MaximumRetryCount > 5
  msg := sprintf("CIS 5.14: Container '%s' has restart retry count > 5 (%d).", [container.Name, container.HostConfig.RestartPolicy.MaximumRetryCount])
}

# CIS 5.15: PID namespace must not be shared with host
deny_host_pid[msg] {
  container := input.containers[_]
  container.HostConfig.PidMode == "host"
  msg := sprintf("CIS 5.15 [CRITICAL]: Container '%s' shares the host PID namespace (--pid=host).", [container.Name])
}

# CIS 5.16: IPC namespace must not be shared with host
deny_host_ipc[msg] {
  container := input.containers[_]
  container.HostConfig.IpcMode == "host"
  msg := sprintf("CIS 5.16 [CRITICAL]: Container '%s' shares the host IPC namespace (--ipc=host).", [container.Name])
}

# CIS 5.20: UTS namespace must not be shared with host
deny_host_uts[msg] {
  container := input.containers[_]
  container.HostConfig.UTSMode == "host"
  msg := sprintf("CIS 5.20: Container '%s' shares the host UTS namespace (--uts=host).", [container.Name])
}

# CIS 5.21: seccomp profile must not be unconfined
deny_seccomp_unconfined[msg] {
  container := input.containers[_]
  sec_opt := container.HostConfig.SecurityOpt[_]
  contains(sec_opt, "seccomp=unconfined")
  msg := sprintf("CIS 5.21: Container '%s' has seccomp disabled (seccomp=unconfined).", [container.Name])
}

deny_seccomp_unconfined[msg] {
  container := input.containers[_]
  sec_opt := container.HostConfig.SecurityOpt[_]
  contains(sec_opt, "seccomp:unconfined")
  msg := sprintf("CIS 5.21: Container '%s' has seccomp disabled (seccomp:unconfined).", [container.Name])
}

# CIS 5.25: no-new-privileges must be set
deny_new_privileges[msg] {
  container := input.containers[_]
  security_opts := container.HostConfig.SecurityOpt
  not has_no_new_privileges(security_opts)
  msg := sprintf("CIS 5.25 [CRITICAL]: Container '%s' does not have 'no-new-privileges' set.", [container.Name])
}

has_no_new_privileges(opts) {
  opt := opts[_]
  contains(opt, "no-new-privileges")
}

# CIS 5.28: PIDs limit must be set
deny_no_pids_limit[msg] {
  container := input.containers[_]
  container.HostConfig.PidsLimit <= 0
  msg := sprintf("CIS 5.28: Container '%s' has no PIDs limit set. Use --pids-limit to prevent fork bombs.", [container.Name])
}

# ============================================================
# Section 2: Daemon Configuration
# ============================================================

# CIS 2.2: Inter-container communication should be disabled
warn_icc_enabled[msg] {
  input.daemon_config.icc == true
  msg := "CIS 2.2: Inter-container communication (ICC) is enabled. Set 'icc: false' in daemon.json."
}

# CIS 2.5: Insecure registries must not be configured
deny_insecure_registry[msg] {
  count(input.daemon_config["insecure-registries"]) > 0
  msg := "CIS 2.5 [CRITICAL]: Insecure registries are configured. Remove 'insecure-registries' from daemon.json."
}

# CIS 2.6: aufs storage driver must not be used
deny_aufs_driver[msg] {
  input.daemon_config["storage-driver"] == "aufs"
  msg := "CIS 2.6: aufs storage driver is in use. Migrate to overlay2."
}

# CIS 2.14: no-new-privileges must be set at daemon level
deny_daemon_new_privileges[msg] {
  input.daemon_config["no-new-privileges"] != true
  msg := "CIS 2.14: 'no-new-privileges' is not enabled in Docker daemon configuration."
}

# CIS 2.15: live-restore must be enabled
warn_no_live_restore[msg] {
  input.daemon_config["live-restore"] != true
  msg := "CIS 2.15: 'live-restore' is not enabled. Enable it in daemon.json for zero-downtime daemon updates."
}

# CIS 2.18: Experimental features must not be enabled in production
deny_experimental[msg] {
  input.daemon_config.experimental == true
  msg := "CIS 2.18: Experimental features are enabled in Docker daemon. Disable in production."
}

# ============================================================
# Aggregated Compliance Report
# ============================================================

# Collect all violations
violations[msg] {
  msg := deny_privileged[_]
}

violations[msg] {
  msg := deny_host_network[_]
}

violations[msg] {
  msg := deny_host_pid[_]
}

violations[msg] {
  msg := deny_host_ipc[_]
}

violations[msg] {
  msg := deny_root_user[_]
}

violations[msg] {
  msg := deny_sensitive_mount[_]
}

violations[msg] {
  msg := deny_new_privileges[_]
}

violations[msg] {
  msg := deny_seccomp_unconfined[_]
}

violations[msg] {
  msg := deny_no_memory_limit[_]
}

violations[msg] {
  msg := deny_no_cpu_limit[_]
}

violations[msg] {
  msg := deny_writable_root[_]
}

violations[msg] {
  msg := deny_restart_policy[_]
}

violations[msg] {
  msg := deny_host_uts[_]
}

violations[msg] {
  msg := deny_no_pids_limit[_]
}

violations[msg] {
  msg := deny_no_healthcheck[_]
}

violations[msg] {
  msg := deny_insecure_registry[_]
}

violations[msg] {
  msg := deny_aufs_driver[_]
}

violations[msg] {
  msg := deny_daemon_new_privileges[_]
}

violations[msg] {
  msg := deny_experimental[_]
}

# Overall compliance: pass only if no violations
compliant {
  count(violations) == 0
}

# Summary report
summary := {
  "compliant": compliant,
  "violation_count": count(violations),
  "violations": violations,
}
