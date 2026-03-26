# CIS Docker Benchmark v1.6.0 - Section 3: Docker Daemon Configuration Files
# InSpec Controls

# ============================================================================
# 3.1 - 3.22: File permissions and ownership checks
# ============================================================================

# CIS 3.1: Ensure that the docker.service file ownership is set to root:root
control 'cis-docker-3-1' do
  impact 0.7
  title 'Ensure docker.service file ownership is set to root:root'
  desc 'The docker.service file contains sensitive parameters that may alter the behavior '\
       'of the Docker daemon. It should be owned by root:root.'

  tag cis: 'CIS-Docker-3.1'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'
  tag section: '3 - Docker Daemon Configuration Files'

  docker_service_file = input('docker_service_file', value: '/lib/systemd/system/docker.service')
  alt_service_file = '/usr/lib/systemd/system/docker.service'

  service_path = file(docker_service_file).exist? ? docker_service_file : alt_service_file

  describe file(service_path) do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

# CIS 3.2: Ensure that docker.service file permissions are appropriately set
control 'cis-docker-3-2' do
  impact 0.7
  title 'Ensure docker.service file permissions are set to 644 or more restrictive'
  desc 'The docker.service file should not be world-writable or group-writable.'

  tag cis: 'CIS-Docker-3.2'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  docker_service_file = input('docker_service_file', value: '/lib/systemd/system/docker.service')
  alt_service_file = '/usr/lib/systemd/system/docker.service'

  service_path = file(docker_service_file).exist? ? docker_service_file : alt_service_file

  describe file(service_path) do
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('other') }
  end
end

# CIS 3.3: Ensure that docker.socket file ownership is set to root:root
control 'cis-docker-3-3' do
  impact 0.7
  title 'Ensure docker.socket file ownership is set to root:root'
  desc 'The docker.socket file enables the Docker daemon to listen via socket. '\
       'It should be owned by root:root.'

  tag cis: 'CIS-Docker-3.3'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  socket_files = [
    '/lib/systemd/system/docker.socket',
    '/usr/lib/systemd/system/docker.socket'
  ]

  socket_file = socket_files.find { |f| file(f).exist? }

  if socket_file
    describe file(socket_file) do
      its('owner') { should eq 'root' }
      its('group') { should eq 'root' }
    end
  else
    describe 'docker.socket file' do
      skip 'docker.socket file not found'
    end
  end
end

# CIS 3.4: Ensure that docker.socket file permissions are set to 644 or more restrictive
control 'cis-docker-3-4' do
  impact 0.7
  title 'Ensure docker.socket file permissions are set to 644 or more restrictive'
  desc 'The docker.socket file should not be group-writable or world-writable.'

  tag cis: 'CIS-Docker-3.4'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  socket_files = [
    '/lib/systemd/system/docker.socket',
    '/usr/lib/systemd/system/docker.socket'
  ]

  socket_file = socket_files.find { |f| file(f).exist? }

  if socket_file
    describe file(socket_file) do
      it { should_not be_writable.by('group') }
      it { should_not be_writable.by('other') }
    end
  else
    describe 'docker.socket permissions' do
      skip 'docker.socket file not found'
    end
  end
end

# CIS 3.5: Ensure that the /etc/docker directory ownership is set to root:root
control 'cis-docker-3-5' do
  impact 0.7
  title 'Ensure /etc/docker directory ownership is set to root:root'
  desc 'The /etc/docker directory holds Docker configuration files. '\
       'It should be owned by root:root to protect against unauthorized modification.'

  tag cis: 'CIS-Docker-3.5'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe file('/etc/docker') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

# CIS 3.6: Ensure that /etc/docker directory permissions are set to 755 or more restrictive
control 'cis-docker-3-6' do
  impact 0.7
  title 'Ensure /etc/docker directory permissions are set to 755 or more restrictive'
  desc 'The /etc/docker directory should not be world-writable or group-writable.'

  tag cis: 'CIS-Docker-3.6'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe file('/etc/docker') do
    it { should exist }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('other') }
  end
end

# CIS 3.7: Ensure that registry certificate file ownership is set to root:root
control 'cis-docker-3-7' do
  impact 0.7
  title 'Ensure registry certificate file ownership is set to root:root'
  desc 'Registry certificate files should be owned by root:root to ensure '\
       'they cannot be tampered with.'

  tag cis: 'CIS-Docker-3.7'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  certs_dir = input('docker_certs_dir', value: '/etc/docker/certs.d')

  if file(certs_dir).exist?
    command("find #{certs_dir} -name '*.cert' -o -name '*.crt' -o -name '*.key'").stdout.split("\n").each do |cert_file|
      describe file(cert_file) do
        its('owner') { should eq 'root' }
        its('group') { should eq 'root' }
      end
    end
  else
    describe 'Docker registry certificates' do
      skip 'No registry certificates directory found'
    end
  end
end

# CIS 3.8: Ensure that registry certificate file permissions are set to 444 or more restrictive
control 'cis-docker-3-8' do
  impact 0.7
  title 'Ensure registry certificate file permissions are set to 444 or more restrictive'
  desc 'Registry certificate files should be read-only to prevent unauthorized modification.'

  tag cis: 'CIS-Docker-3.8'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  certs_dir = input('docker_certs_dir', value: '/etc/docker/certs.d')

  if file(certs_dir).exist?
    command("find #{certs_dir} -name '*.cert' -o -name '*.crt'").stdout.split("\n").each do |cert_file|
      describe file(cert_file) do
        it { should_not be_writable.by('owner') }
        it { should_not be_writable.by('group') }
        it { should_not be_writable.by('other') }
      end
    end
  else
    describe 'Docker registry certificate permissions' do
      skip 'No registry certificates directory found'
    end
  end
end

# CIS 3.9: Ensure that TLS CA certificate file ownership is set to root:root
control 'cis-docker-3-9' do
  impact 0.9
  title 'Ensure TLS CA certificate file ownership is set to root:root'
  desc 'The TLS CA certificate file should be owned by root:root to prevent unauthorized modification.'

  tag cis: 'CIS-Docker-3.9'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    ca_cert = json(daemon_conf)['tlscacert']
    if ca_cert
      describe file(ca_cert) do
        its('owner') { should eq 'root' }
        its('group') { should eq 'root' }
      end
    else
      describe 'TLS CA certificate' do
        skip 'TLS not configured'
      end
    end
  else
    describe 'Docker TLS CA cert ownership' do
      skip 'Docker daemon.json not found'
    end
  end
end

# CIS 3.15: Ensure that the Docker socket file ownership is set to root:docker
control 'cis-docker-3-15' do
  impact 0.9
  title 'Ensure Docker socket file ownership is set to root:docker'
  desc 'The Docker socket file should be owned by root and belong to the docker group. '\
       'This prevents unauthorized access to the Docker daemon.'

  tag cis: 'CIS-Docker-3.15'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  docker_socket = input('docker_socket_file', value: '/var/run/docker.sock')

  describe file(docker_socket) do
    its('owner') { should eq 'root' }
    its('group') { should eq 'docker' }
  end
end

# CIS 3.16: Ensure that the Docker socket file permissions are set to 660 or more restrictive
control 'cis-docker-3-16' do
  impact 0.9
  title 'Ensure Docker socket file permissions are set to 660 or more restrictive'
  desc 'The Docker socket file should not be world-readable or world-writable.'

  tag cis: 'CIS-Docker-3.16'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  docker_socket = input('docker_socket_file', value: '/var/run/docker.sock')

  describe file(docker_socket) do
    it { should_not be_readable.by('other') }
    it { should_not be_writable.by('other') }
  end
end

# CIS 3.17: Ensure that the daemon.json file ownership is set to root:root
control 'cis-docker-3-17' do
  impact 0.7
  title 'Ensure daemon.json file ownership is set to root:root'
  desc 'The daemon.json file contains sensitive Docker daemon configuration. '\
       'It should be owned by root:root.'

  tag cis: 'CIS-Docker-3.17'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    describe file(daemon_conf) do
      its('owner') { should eq 'root' }
      its('group') { should eq 'root' }
    end
  else
    describe 'daemon.json' do
      skip 'daemon.json file not found'
    end
  end
end

# CIS 3.18: Ensure that daemon.json file permissions are set to 644 or more restrictive
control 'cis-docker-3-18' do
  impact 0.7
  title 'Ensure daemon.json file permissions are set to 644 or more restrictive'
  desc 'The daemon.json file should not be group-writable or world-writable.'

  tag cis: 'CIS-Docker-3.18'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf = input('docker_daemon_conf', value: '/etc/docker/daemon.json')

  if file(daemon_conf).exist?
    describe file(daemon_conf) do
      it { should_not be_writable.by('group') }
      it { should_not be_writable.by('other') }
    end
  else
    describe 'daemon.json permissions' do
      skip 'daemon.json file not found'
    end
  end
end
