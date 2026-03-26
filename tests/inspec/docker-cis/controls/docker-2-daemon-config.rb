# CIS Docker Benchmark v1.6.0 - Section 2: Docker Daemon Configuration
# InSpec Controls

# ============================================================================
# 2.1 Docker Daemon Configuration
# ============================================================================

# CIS 2.1: Run the Docker daemon as a non-root user, if possible (Rootless mode)
control 'cis-docker-2-1' do
  impact 0.5
  title 'Run the Docker daemon as a non-root user (Rootless mode)'
  desc 'Running the Docker daemon as a non-root user mitigates potential vulnerabilities '\
       'in the daemon by eliminating the full root access available to the current default configuration.'

  tag cis: 'CIS-Docker-2.1'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'
  tag section: '2 - Docker Daemon Configuration'

  # This is informational - check if rootless is configured or document exception
  describe command('docker info --format "{{.SecurityOptions}}"') do
    its('exit_status') { should eq 0 }
  end
end

# CIS 2.2: Ensure network traffic is restricted between containers on the default bridge network
control 'cis-docker-2-2' do
  impact 0.7
  title 'Ensure network traffic is restricted between containers on the default bridge'
  desc 'By default, all network traffic is allowed between containers on the same host on the default bridge network. '\
       'This should be restricted using the --icc=false option or user-defined networks.'

  tag cis: 'CIS-Docker-2.2'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    describe json(daemon_conf) do
      its(['icc']) { should eq false }
    end
  else
    describe command('ps -ef | grep dockerd | grep -v grep') do
      its('stdout') { should match /--icc=false/ }
    end
  end
end

# CIS 2.3: Ensure the logging level is set to 'info'
control 'cis-docker-2-3' do
  impact 0.5
  title 'Ensure the logging level is set to info'
  desc 'Set Docker daemon log level to info. A value other than info could result in either '\
       'a loss of information or too much information in logs.'

  tag cis: 'CIS-Docker-2.3'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    describe json(daemon_conf) do
      its(['log-level']) { should be_in ['info', nil] }
    end
  else
    describe command('ps -ef | grep dockerd | grep -v grep') do
      its('stdout') { should_not match /--log-level=debug/ }
    end
  end
end

# CIS 2.4: Ensure Docker is allowed to make changes to iptables
control 'cis-docker-2-4' do
  impact 0.7
  title 'Ensure Docker is allowed to make changes to iptables'
  desc 'Allowing Docker to make iptable changes ensures that Docker can create the '\
       'necessary network rules for container connectivity and isolation.'

  tag cis: 'CIS-Docker-2.4'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    describe json(daemon_conf) do
      its(['iptables']) { should_not eq false }
    end
  else
    describe command('ps -ef | grep dockerd | grep -v grep') do
      its('stdout') { should_not match /--iptables=false/ }
    end
  end
end

# CIS 2.5: Ensure insecure registries are not used
control 'cis-docker-2-5' do
  impact 0.9
  title 'Ensure insecure registries are not used'
  desc 'Docker considers a private registry as insecure if the registry has no TLS. '\
       'Insecure registries should not be used in production environments.'

  tag cis: 'CIS-Docker-2.5'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    describe json(daemon_conf) do
      its(['insecure-registries']) { should be_nil }
    end
  else
    describe command('ps -ef | grep dockerd | grep -v grep') do
      its('stdout') { should_not match /--insecure-registry/ }
    end
  end
end

# CIS 2.6: Ensure aufs storage driver is not used
control 'cis-docker-2-6' do
  impact 0.7
  title 'Ensure aufs storage driver is not used'
  desc 'The aufs storage driver is not recommended. Use more modern alternatives '\
       'such as overlay2.'

  tag cis: 'CIS-Docker-2.6'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe command('docker info --format "{{.Driver}}"') do
    its('stdout') { should_not match /aufs/ }
  end
end

# CIS 2.7: Ensure TLS authentication for Docker daemon is configured
control 'cis-docker-2-7' do
  impact 0.9
  title 'Ensure TLS authentication for Docker daemon is configured'
  desc 'It is possible to make the Docker daemon to listen on a specific IP and port. '\
       'If the daemon is bound to a TCP socket, TLS should be configured to secure communications.'

  tag cis: 'CIS-Docker-2.7'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  # Check if Docker is listening on a TCP socket
  tcp_listening = command('ps -ef | grep dockerd | grep -E "tcp://|0.0.0.0" | grep -v grep').exit_status == 0

  if tcp_listening
    if file(daemon_conf).exist?
      describe json(daemon_conf) do
        its(['tls']) { should eq true }
        its(['tlscert']) { should_not be_nil }
        its(['tlskey']) { should_not be_nil }
        its(['tlscacert']) { should_not be_nil }
        its(['tlsverify']) { should eq true }
      end
    end
  else
    describe 'Docker daemon TLS' do
      it 'is not required (not listening on TCP)' do
        expect(true).to eq true
      end
    end
  end
end

# CIS 2.8: Ensure the default ulimit is configured appropriately
control 'cis-docker-2-8' do
  impact 0.5
  title 'Ensure the default ulimit is configured appropriately'
  desc 'Setting default ulimits limits resource consumption for containers '\
       'to prevent denial of service conditions.'

  tag cis: 'CIS-Docker-2.8'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    describe json(daemon_conf) do
      its(['default-ulimits']) { should_not be_nil }
    end
  else
    describe 'Docker ulimits' do
      skip 'Review default ulimits configuration for your environment'
    end
  end
end

# CIS 2.9: Enable user namespace support
control 'cis-docker-2-9' do
  impact 0.7
  title 'Enable user namespace support'
  desc 'Enabling user namespaces provides additional isolation between the container '\
       'and the host by remapping container UIDs to higher unprivileged UIDs on the host.'

  tag cis: 'CIS-Docker-2.9'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    describe json(daemon_conf) do
      its(['userns-remap']) { should_not be_nil }
    end
  else
    describe command('ps -ef | grep dockerd | grep -v grep') do
      its('stdout') { should match /--userns-remap/ }
    end
  end
end

# CIS 2.10: Ensure the default cgroup usage has been confirmed
control 'cis-docker-2-10' do
  impact 0.5
  title 'Ensure the default cgroup usage has been confirmed'
  desc 'The --cgroup-parent option specifies the cgroup that containers will run in. '\
       'It should be confirmed that the correct cgroup parent is being used.'

  tag cis: 'CIS-Docker-2.10'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe command('docker info --format "{{.CgroupDriver}}"') do
    its('stdout') { should match /systemd|cgroupfs/ }
  end
end

# CIS 2.11: Ensure base device size is not changed until needed
control 'cis-docker-2-11' do
  impact 0.5
  title 'Ensure base device size is not changed until needed'
  desc 'The --storage-opt dm.basesize option limits the amount of disk space '\
       'each container can use. Do not change this unless required.'

  tag cis: 'CIS-Docker-2.11'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    describe json(daemon_conf) do
      its(['storage-opts']) { should be_nil }
    end
  else
    describe command('ps -ef | grep dockerd | grep -v grep') do
      its('stdout') { should_not match /dm\.basesize/ }
    end
  end
end

# CIS 2.12: Ensure that authorization for Docker client commands is enabled
control 'cis-docker-2-12' do
  impact 0.7
  title 'Ensure that authorization for Docker client commands is enabled'
  desc 'Use native Docker authorization plugins or third-party authorization mechanisms '\
       'to manage access to Docker daemon commands.'

  tag cis: 'CIS-Docker-2.12'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    describe json(daemon_conf) do
      its(['authorization-plugins']) { should_not be_nil }
    end
  else
    describe 'Docker authorization plugin' do
      skip 'Review whether Docker authorization plugins are required in your environment'
    end
  end
end

# CIS 2.13: Ensure centralized and remote logging is configured
control 'cis-docker-2-13' do
  impact 0.7
  title 'Ensure centralized and remote logging is configured'
  desc 'Docker supports multiple logging drivers for centralized log management. '\
       'Configure a remote logging driver to ensure log persistence and availability.'

  tag cis: 'CIS-Docker-2.13'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe command('docker info --format "{{.LoggingDriver}}"') do
    its('stdout') { should_not match /^$/ }
  end
end

# CIS 2.14: Ensure containers are restricted from acquiring new privileges
control 'cis-docker-2-14' do
  impact 0.9
  title 'Ensure containers are restricted from acquiring new privileges'
  desc 'Restrict containers from acquiring additional privileges via suid or sgid bits '\
       'by setting the --no-new-privileges option on the Docker daemon.'

  tag cis: 'CIS-Docker-2.14'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    describe json(daemon_conf) do
      its(['no-new-privileges']) { should eq true }
    end
  else
    describe command('ps -ef | grep dockerd | grep -v grep') do
      its('stdout') { should match /--no-new-privileges/ }
    end
  end
end

# CIS 2.15: Ensure live restore is enabled
control 'cis-docker-2-15' do
  impact 0.5
  title 'Ensure live restore is enabled'
  desc 'Enabling --live-restore allows containers to remain running even when the Docker daemon is down.'

  tag cis: 'CIS-Docker-2.15'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    describe json(daemon_conf) do
      its(['live-restore']) { should eq true }
    end
  else
    describe command('ps -ef | grep dockerd | grep -v grep') do
      its('stdout') { should match /--live-restore/ }
    end
  end
end

# CIS 2.16: Ensure Userland Proxy is disabled
control 'cis-docker-2-16' do
  impact 0.5
  title 'Ensure Userland Proxy is disabled'
  desc 'The Docker daemon starts a userland proxy service for port forwarding whenever a port is exposed. '\
       'Disabling the proxy reduces the attack surface if unnecessary.'

  tag cis: 'CIS-Docker-2.16'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    describe json(daemon_conf) do
      its(['userland-proxy']) { should eq false }
    end
  else
    describe command('ps -ef | grep dockerd | grep -v grep') do
      its('stdout') { should match /--userland-proxy=false/ }
    end
  end
end

# CIS 2.17: Ensure that a daemon-wide custom seccomp profile is applied
control 'cis-docker-2-17' do
  impact 0.5
  title 'Ensure that a daemon-wide custom seccomp profile is applied'
  desc 'A seccomp profile limits the host surface area reachable from the container '\
       'by restricting system calls.'

  tag cis: 'CIS-Docker-2.17'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe command('docker info --format "{{.SecurityOptions}}"') do
    its('stdout') { should match /seccomp/ }
  end
end

# CIS 2.18: Ensure that experimental features are not enabled in production
control 'cis-docker-2-18' do
  impact 0.5
  title 'Ensure that experimental features are not enabled in production'
  desc 'Experimental features may be less stable and secure than production-ready features.'

  tag cis: 'CIS-Docker-2.18'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe command('docker info --format "{{.ExperimentalBuild}}"') do
    its('stdout') { should match /false/ }
  end
end
