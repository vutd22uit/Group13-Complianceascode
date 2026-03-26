# CIS Docker Benchmark v1.6.0 - Section 5: Container Runtime
# InSpec Controls

# ============================================================================
# 5.1 - 5.31: Container Runtime Security
# ============================================================================

# CIS 5.1: Ensure that, if applicable, an AppArmor profile is enabled
control 'cis-docker-5-1' do
  impact 0.9
  title 'Ensure AppArmor Profile is enabled for containers'
  desc 'AppArmor is a Linux Security Module that provides Mandatory Access Control (MAC) for programs. '\
       'If the host system uses AppArmor, containers should have an AppArmor profile applied.'

  tag cis: 'CIS-Docker-5.1'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'
  tag section: '5 - Container Runtime'

  # Check if AppArmor is available on the host
  if file('/sys/kernel/security/apparmor').exist?
    running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

    if running_containers.empty?
      describe 'Running containers' do
        skip 'No running containers found'
      end
    else
      running_containers.each do |container_id|
        describe command("docker inspect --format='{{.AppArmorProfile}}' #{container_id}") do
          its('stdout') { should_not match /^$/ }
          its('stdout') { should_not match /unconfined/ }
        end
      end
    end
  else
    describe 'AppArmor' do
      skip 'AppArmor is not available on this host'
    end
  end
end

# CIS 5.2: Ensure that, if applicable, SELinux security options are set
control 'cis-docker-5-2' do
  impact 0.9
  title 'Ensure SELinux security options are set for containers'
  desc 'SELinux provides Mandatory Access Control (MAC) for containers. '\
       'If the host uses SELinux, containers should have SELinux options configured.'

  tag cis: 'CIS-Docker-5.2'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  if command('which getenforce').exit_status == 0
    selinux_status = command('getenforce').stdout.strip

    if selinux_status =~ /Enforcing|Permissive/
      running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

      unless running_containers.empty?
        running_containers.each do |container_id|
          describe command("docker inspect --format='{{.HostConfig.SecurityOpt}}' #{container_id}") do
            its('stdout') { should match /label:/ }
          end
        end
      end
    else
      describe 'SELinux' do
        skip 'SELinux is disabled on this host'
      end
    end
  else
    describe 'SELinux' do
      skip 'SELinux is not available on this host'
    end
  end
end

# CIS 5.3: Ensure Linux Kernel Capabilities are restricted within containers
control 'cis-docker-5-3' do
  impact 0.9
  title 'Ensure Linux Kernel Capabilities are restricted within containers'
  desc 'By default, Docker runs with a restricted set of Linux capabilities. '\
       'Containers should not be run with additional capabilities unless absolutely necessary.'

  tag cis: 'CIS-Docker-5.3'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.HostConfig.CapAdd}}' #{container_id}") do
        its('stdout') { should match /\[\]|<nil>/ }
      end
    end
  end
end

# CIS 5.4: Ensure that privileged containers are not used
control 'cis-docker-5-4' do
  impact 1.0
  title 'Ensure that privileged containers are not used'
  desc 'Running a container in privileged mode grants the container all capabilities '\
       'on the host system, effectively removing all security protections.'

  tag cis: 'CIS-Docker-5.4'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.HostConfig.Privileged}}' #{container_id}") do
        its('stdout') { should match /false/ }
      end
    end
  end
end

# CIS 5.5: Ensure sensitive host system directories are not mounted on containers
control 'cis-docker-5-5' do
  impact 0.9
  title 'Ensure sensitive host system directories are not mounted on containers'
  desc 'Sensitive host directories should not be mounted on containers. '\
       'Mounting sensitive directories could expose critical host data to the container.'

  tag cis: 'CIS-Docker-5.5'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  sensitive_dirs = ['/', '/boot', '/dev', '/etc', '/lib', '/proc', '/sys', '/usr']

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      sensitive_dirs.each do |dir|
        describe command("docker inspect --format='{{range .Mounts}}{{if eq .Source \"#{dir}\"}}FOUND{{end}}{{end}}' #{container_id}") do
          its('stdout') { should_not match /FOUND/ }
        end
      end
    end
  end
end

# CIS 5.6: Ensure sshd is not run within containers
control 'cis-docker-5-6' do
  impact 0.7
  title 'Ensure sshd is not run within containers'
  desc 'SSH should not be run within containers. For debugging, use docker exec instead. '\
       'Running sshd in containers increases the attack surface.'

  tag cis: 'CIS-Docker-5.6'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker exec #{container_id} ps -ef 2>/dev/null | grep sshd | grep -v grep") do
        its('stdout') { should be_empty }
      end
    end
  end
end

# CIS 5.7: Ensure privileged ports are not mapped within containers
control 'cis-docker-5-7' do
  impact 0.5
  title 'Ensure privileged ports are not mapped within containers'
  desc 'TCP/UDP ports below 1024 are privileged ports. Containers should not bind to '\
       'privileged ports on the host unless there is an explicit need.'

  tag cis: 'CIS-Docker-5.7'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe command('docker ps --format "{{.Ports}}" 2>/dev/null | grep -E "0\.0\.0\.0:[0-9]{1,3}->"') do
    its('stdout') { should be_empty }
  end
end

# CIS 5.9: Ensure the host's network namespace is not shared
control 'cis-docker-5-9' do
  impact 0.9
  title 'Ensure the host network namespace is not shared'
  desc 'If the host network namespace is shared (--net=host), the container has full '\
       'access to the host network stack, which could allow container breakout.'

  tag cis: 'CIS-Docker-5.9'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.HostConfig.NetworkMode}}' #{container_id}") do
        its('stdout') { should_not match /host/ }
      end
    end
  end
end

# CIS 5.10: Ensure memory usage for container is limited
control 'cis-docker-5-10' do
  impact 0.7
  title 'Ensure memory usage for container is limited'
  desc 'Container memory should be limited to prevent a single container from consuming '\
       'all available host memory, which could cause a denial of service.'

  tag cis: 'CIS-Docker-5.10'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.HostConfig.Memory}}' #{container_id}") do
        its('stdout') { should_not match /^0$/ }
      end
    end
  end
end

# CIS 5.11: Ensure CPU priority is set appropriately on the container
control 'cis-docker-5-11' do
  impact 0.5
  title 'Ensure CPU priority is set appropriately on the container'
  desc 'By default, containers are allowed to use unlimited CPU time. '\
       'Setting CPU shares ensures fair resource allocation.'

  tag cis: 'CIS-Docker-5.11'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.HostConfig.CpuShares}}' #{container_id}") do
        its('stdout') { should_not match /^0$/ }
      end
    end
  end
end

# CIS 5.12: Ensure the container's root filesystem is mounted as read only
control 'cis-docker-5-12' do
  impact 0.7
  title 'Ensure the container root filesystem is mounted as read only'
  desc 'Mounting the container root filesystem as read-only prevents container processes '\
       'from writing to the root filesystem, reducing the impact of container compromise.'

  tag cis: 'CIS-Docker-5.12'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.HostConfig.ReadonlyRootfs}}' #{container_id}") do
        its('stdout') { should match /true/ }
      end
    end
  end
end

# CIS 5.14: Ensure 'on-failure' container restart policy is set to '5'
control 'cis-docker-5-14' do
  impact 0.5
  title 'Ensure on-failure container restart policy is set to 5'
  desc 'Using on-failure restart policy limits restart attempts to prevent resource exhaustion. '\
       'Setting the restart count to 5 helps detect and prevent infinite restart loops.'

  tag cis: 'CIS-Docker-5.14'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  max_restarts = input('max_container_restart', value: 5)

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      restart_policy = command("docker inspect --format='{{.HostConfig.RestartPolicy.Name}}' #{container_id}").stdout.strip
      restart_count = command("docker inspect --format='{{.HostConfig.RestartPolicy.MaximumRetryCount}}' #{container_id}").stdout.strip.to_i

      if restart_policy == 'always' || restart_policy == 'unless-stopped'
        describe "Container #{container_id} restart policy" do
          it 'should not use always or unless-stopped without retry limit' do
            expect(restart_policy).not_to eq('always')
          end
        end
      elsif restart_policy == 'on-failure'
        describe "Container #{container_id} restart count" do
          it "should be #{max_restarts} or less" do
            expect(restart_count).to be <= max_restarts
          end
        end
      end
    end
  end
end

# CIS 5.15: Ensure the host's process namespace is not shared
control 'cis-docker-5-15' do
  impact 0.9
  title 'Ensure the host process namespace is not shared'
  desc 'If --pid=host is set, the container shares the host process namespace, '\
       'allowing it to see and interact with all processes on the host.'

  tag cis: 'CIS-Docker-5.15'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.HostConfig.PidMode}}' #{container_id}") do
        its('stdout') { should_not match /host/ }
      end
    end
  end
end

# CIS 5.16: Ensure the host's IPC namespace is not shared
control 'cis-docker-5-16' do
  impact 0.9
  title 'Ensure the host IPC namespace is not shared'
  desc 'If --ipc=host is set, the container shares the host IPC namespace, '\
       'potentially allowing it to interact with host processes via shared memory.'

  tag cis: 'CIS-Docker-5.16'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.HostConfig.IpcMode}}' #{container_id}") do
        its('stdout') { should_not match /^host$/ }
      end
    end
  end
end

# CIS 5.20: Ensure the host's UTS namespace is not shared
control 'cis-docker-5-20' do
  impact 0.5
  title 'Ensure the host UTS namespace is not shared'
  desc 'UTS namespaces provide isolation of hostnames and domain names. '\
       'Sharing the host UTS namespace allows a container to change the hostname of the host system.'

  tag cis: 'CIS-Docker-5.20'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.HostConfig.UTSMode}}' #{container_id}") do
        its('stdout') { should_not match /host/ }
      end
    end
  end
end

# CIS 5.21: Ensure the default seccomp profile is not disabled
control 'cis-docker-5-21' do
  impact 0.7
  title 'Ensure the default seccomp profile is not disabled'
  desc 'The seccomp profile filters system calls that a container can make, '\
       'reducing the attack surface. The default profile should not be disabled.'

  tag cis: 'CIS-Docker-5.21'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.HostConfig.SecurityOpt}}' #{container_id}") do
        its('stdout') { should_not match /seccomp:unconfined/ }
        its('stdout') { should_not match /seccomp=unconfined/ }
      end
    end
  end
end

# CIS 5.25: Ensure the container is restricted from acquiring additional privileges
control 'cis-docker-5-25' do
  impact 0.9
  title 'Ensure the container is restricted from acquiring additional privileges'
  desc 'Restricting containers from acquiring additional privileges prevents privilege '\
       'escalation attacks using setuid/setgid bits.'

  tag cis: 'CIS-Docker-5.25'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.HostConfig.SecurityOpt}}' #{container_id}") do
        its('stdout') { should match /no-new-privileges/ }
      end
    end
  end
end

# CIS 5.26: Ensure container health is checked at runtime
control 'cis-docker-5-26' do
  impact 0.5
  title 'Ensure container health is checked at runtime'
  desc 'Health checks allow Docker to monitor the status of running containers '\
       'and restart unhealthy containers automatically.'

  tag cis: 'CIS-Docker-5.26'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.State.Health}}' #{container_id}") do
        its('stdout') { should_not match /^<nil>$/ }
      end
    end
  end
end

# CIS 5.28: Ensure PIDs cgroup limit is used
control 'cis-docker-5-28' do
  impact 0.5
  title 'Ensure PIDs cgroup limit is used'
  desc 'Setting a PID limit prevents fork bombs and denial of service attacks '\
       'by limiting the number of processes a container can create.'

  tag cis: 'CIS-Docker-5.28'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.HostConfig.PidsLimit}}' #{container_id}") do
        its('stdout') { should_not match /^(-1|0)$/ }
      end
    end
  end
end
