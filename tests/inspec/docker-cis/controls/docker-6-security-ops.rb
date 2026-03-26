# CIS Docker Benchmark v1.6.0 - Section 6: Docker Security Operations
# InSpec Controls

# ============================================================================
# 6.1 - 6.2: Docker Security Operations
# ============================================================================

# CIS 6.1: Ensure image vulnerability scanning is performed
control 'cis-docker-6-1' do
  impact 0.9
  title 'Ensure image vulnerability scanning is performed regularly'
  desc 'Container images should be scanned for vulnerabilities before deployment and '\
       'regularly thereafter to ensure no known vulnerabilities are present.'

  tag cis: 'CIS-Docker-6.1'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'
  tag section: '6 - Docker Security Operations'

  # Verify at least one vulnerability scanner is present
  describe.one do
    describe command('which trivy') do
      its('exit_status') { should eq 0 }
    end
    describe command('which grype') do
      its('exit_status') { should eq 0 }
    end
    describe command('which snyk') do
      its('exit_status') { should eq 0 }
    end
    describe command('which anchore-cli') do
      its('exit_status') { should eq 0 }
    end
    describe command('which clair-scanner') do
      its('exit_status') { should eq 0 }
    end
  end
end

# CIS 6.2: Ensure that container sprawl is avoided
control 'cis-docker-6-2' do
  impact 0.5
  title 'Ensure that container sprawl is avoided'
  desc 'Large numbers of unused containers should be cleaned up. '\
       'Container sprawl increases the attack surface and complicates patch management.'

  tag cis: 'CIS-Docker-6.2'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  # Check the number of stopped (unused) containers
  stopped_container_count = command('docker ps -a --filter "status=exited" --quiet 2>/dev/null | wc -l').stdout.strip.to_i

  describe 'Stopped container count' do
    it 'should be kept minimal (less than 10 stopped containers)' do
      expect(stopped_container_count).to be < 10
    end
  end
end

# Additional: Ensure Docker Content Trust is enforced in production
control 'cis-docker-6-3' do
  impact 0.7
  title 'Ensure Docker Content Trust is enforced'
  desc 'Docker Content Trust (DCT) enforces image signature verification when pushing '\
       'and pulling images. This ensures you only use trusted images.'

  tag cis: 'CIS-Docker-6.3'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  # DOCKER_CONTENT_TRUST should be set to 1 in environment
  describe command('printenv DOCKER_CONTENT_TRUST') do
    its('stdout') { should match /1/ }
  end
end

# Additional: Ensure Docker audit logs are reviewed
control 'cis-docker-6-4' do
  impact 0.5
  title 'Ensure Docker audit logs are reviewed regularly'
  desc 'Docker daemon and container logs should be reviewed regularly for '\
       'suspicious activity, failed authentications, and unusual patterns.'

  tag cis: 'CIS-Docker-6.4'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  # Ensure Docker logging is configured
  describe command('docker info --format "{{.LoggingDriver}}" 2>/dev/null') do
    its('exit_status') { should eq 0 }
    its('stdout') { should_not match /^$/ }
    its('stdout') { should_not match /none/ }
  end
end

# Additional: Ensure Docker daemon TLS certificates are not expired
control 'cis-docker-6-5' do
  impact 0.9
  title 'Ensure Docker daemon TLS certificates are valid and not expired'
  desc 'TLS certificates used by the Docker daemon should be valid and not expired '\
       'to ensure secure communications.'

  tag cis: 'CIS-Docker-6.5'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  daemon_conf_file = '/etc/docker/daemon.json'

  if file(daemon_conf_file).exist?
    daemon_conf = json(daemon_conf_file)
    tls_cert = daemon_conf['tlscert']

    if tls_cert && file(tls_cert).exist?
      describe command("openssl x509 -noout -checkend 2592000 -in #{tls_cert}") do
        its('exit_status') { should eq 0 }
      end
    else
      describe 'TLS certificate validation' do
        skip 'TLS certificates not configured for Docker daemon'
      end
    end
  else
    describe 'Docker daemon TLS' do
      skip 'Docker daemon.json not found'
    end
  end
end
