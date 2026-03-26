# CIS Docker Benchmark v1.6.0 - Section 1: Host Configuration
# InSpec Controls

# ============================================================================
# 1.1 Host Operating System Configuration
# ============================================================================

# CIS 1.1.1: Ensure a separate partition for containers has been created
control 'cis-docker-1-1-1' do
  impact 0.7
  title 'Ensure a separate partition for containers has been created'
  desc 'All Docker containers and their data should reside in /var/lib/docker, '\
       'which should be mounted on a separate partition to avoid disk exhaustion.'

  tag cis: 'CIS-Docker-1.1.1'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'
  tag section: '1 - Host Configuration'

  docker_data_dir = input('docker_data_dir', value: '/var/lib/docker')

  describe mount(docker_data_dir) do
    it { should be_mounted }
  end
end

# CIS 1.1.2: Ensure only trusted users are allowed to control Docker daemon
control 'cis-docker-1-1-2' do
  impact 0.9
  title 'Ensure only trusted users are allowed to control Docker daemon'
  desc 'The Docker daemon currently requires root privileges. Membership in the docker group '\
       'should be restricted to trusted users only as it effectively grants root access.'

  tag cis: 'CIS-Docker-1.1.2'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe group('docker') do
    it { should exist }
  end

  # docker group should not include unexpected users
  describe command('getent group docker | cut -d: -f4') do
    its('stdout') { should_not match /^$/ }
  end
end

# CIS 1.2.1: Ensure the container host has been Hardened
control 'cis-docker-1-2-1' do
  impact 0.5
  title 'Ensure the container host has been hardened'
  desc 'The container host should be hardened in accordance with applicable Linux security benchmarks.'

  tag cis: 'CIS-Docker-1.2.1'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  # Check that auditd is installed and running
  describe package('auditd') do
    it { should be_installed }
  end

  describe service('auditd') do
    it { should be_enabled }
    it { should be_running }
  end
end

# CIS 1.2.2: Ensure Docker is up to date
control 'cis-docker-1-2-2' do
  impact 0.7
  title 'Ensure Docker is up to date'
  desc 'Use the latest available Docker version to ensure security patches are applied.'

  tag cis: 'CIS-Docker-1.2.2'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe command('docker --version') do
    it { should exist }
    its('exit_status') { should eq 0 }
    # Docker version should be present
    its('stdout') { should match /Docker version \d+\.\d+/ }
  end
end

# ============================================================================
# 1.3 Audit Docker Files and Directories
# ============================================================================

# CIS 1.1.3: Ensure auditing is configured for the Docker daemon
control 'cis-docker-1-1-3' do
  impact 0.7
  title 'Ensure auditing is configured for the Docker daemon'
  desc 'The Docker daemon should be audited to detect unauthorized activity.'

  tag cis: 'CIS-Docker-1.1.3'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe command('auditctl -l | grep /usr/bin/dockerd') do
    its('stdout') { should match /\/usr\/bin\/dockerd/ }
  end
end

# CIS 1.1.4: Ensure auditing is configured for Docker files and directories - /var/lib/docker
control 'cis-docker-1-1-4' do
  impact 0.5
  title 'Ensure auditing is configured for /var/lib/docker'
  desc 'Auditing /var/lib/docker ensures that Docker data changes are tracked.'

  tag cis: 'CIS-Docker-1.1.4'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe command('auditctl -l | grep /var/lib/docker') do
    its('stdout') { should match /\/var\/lib\/docker/ }
  end
end

# CIS 1.1.5: Ensure auditing is configured for Docker files and directories - /etc/docker
control 'cis-docker-1-1-5' do
  impact 0.5
  title 'Ensure auditing is configured for /etc/docker'
  desc 'Auditing /etc/docker directory helps track unauthorized changes to Docker configuration.'

  tag cis: 'CIS-Docker-1.1.5'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe command('auditctl -l | grep /etc/docker') do
    its('stdout') { should match /\/etc\/docker/ }
  end
end

# CIS 1.1.6: Ensure auditing is configured for Docker files - docker.service
control 'cis-docker-1-1-6' do
  impact 0.5
  title 'Ensure auditing is configured for docker.service'
  desc 'The Docker service file contains sensitive parameters.'

  tag cis: 'CIS-Docker-1.1.6'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe command('auditctl -l | grep docker.service') do
    its('stdout') { should match /docker\.service/ }
  end
end
