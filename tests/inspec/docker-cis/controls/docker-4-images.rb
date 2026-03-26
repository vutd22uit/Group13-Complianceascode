# CIS Docker Benchmark v1.6.0 - Section 4: Container Images and Build Files
# InSpec Controls

# ============================================================================
# 4.1 - 4.11: Container Image and Dockerfile Security
# ============================================================================

# CIS 4.1: Ensure that a user for the container has been created
control 'cis-docker-4-1' do
  impact 0.9
  title 'Ensure that a user for the container has been created'
  desc 'Containers should run as a non-root user. Running containers as root presents '\
       'a security risk as any process that breaks out of the container will run as root on the host.'

  tag cis: 'CIS-Docker-4.1'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'
  tag section: '4 - Container Images and Build Files'

  # Check all running containers are not running as root
  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.Config.User}}' #{container_id}") do
        its('stdout') { should_not match /^$/ }
        its('stdout') { should_not match /^root$/ }
        its('stdout') { should_not match /^0$/ }
      end
    end
  end
end

# CIS 4.2: Ensure that containers use only trusted base images
control 'cis-docker-4-2' do
  impact 0.7
  title 'Ensure that containers use only trusted base images'
  desc 'Only trusted and validated base images should be used for Docker containers. '\
       'Untrusted images may contain malicious software or vulnerabilities.'

  tag cis: 'CIS-Docker-4.2'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  # Ensure Docker Content Trust is enabled
  describe command('echo $DOCKER_CONTENT_TRUST') do
    its('stdout') { should match /1/ }
  end
end

# CIS 4.3: Ensure that unnecessary packages are not installed in the container
control 'cis-docker-4-3' do
  impact 0.5
  title 'Ensure that unnecessary packages are not installed in the container'
  desc 'Keeping Docker images lean by installing only what is required reduces the '\
       'attack surface of the container.'

  tag cis: 'CIS-Docker-4.3'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  # This is a process/review check - document that images are reviewed for unnecessary packages
  describe 'Container image minimal package policy' do
    skip 'Manual review required: Ensure images only contain necessary packages. '\
         'Use multi-stage builds and minimal base images (e.g., alpine, distroless).'
  end
end

# CIS 4.4: Ensure images are scanned and rebuilt to include security patches
control 'cis-docker-4-4' do
  impact 0.9
  title 'Ensure images are scanned and rebuilt to include security patches'
  desc 'Container images should be regularly scanned for vulnerabilities and rebuilt '\
       'to include the latest security patches.'

  tag cis: 'CIS-Docker-4.4'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  # Check if a vulnerability scanner is available
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
  end
end

# CIS 4.5: Ensure Content trust for Docker is enabled
control 'cis-docker-4-5' do
  impact 0.9
  title 'Ensure Content trust for Docker is enabled'
  desc 'Content trust provides the ability to use digital signatures for data sent to '\
       'and received from remote Docker registries. It enforces image integrity and publisher verification.'

  tag cis: 'CIS-Docker-4.5'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe command('echo $DOCKER_CONTENT_TRUST') do
    its('stdout') { should match /1/ }
  end
end

# CIS 4.6: Ensure that HEALTHCHECK instructions have been added to the container image
control 'cis-docker-4-6' do
  impact 0.5
  title 'Ensure HEALTHCHECK instructions have been added to container images'
  desc 'Adding HEALTHCHECK instructions to a container image allows Docker to check '\
       'the health of running containers and take action if they become unhealthy.'

  tag cis: 'CIS-Docker-4.6'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    running_containers.each do |container_id|
      describe command("docker inspect --format='{{.Config.Healthcheck}}' #{container_id}") do
        its('stdout') { should_not match /^<nil>$/ }
        its('stdout') { should_not match /^\{\}$/ }
      end
    end
  end
end

# CIS 4.7: Ensure update instructions are not used alone in the Dockerfile
control 'cis-docker-4-7' do
  impact 0.5
  title 'Ensure update instructions are not used alone in the Dockerfile'
  desc 'Using update alone (e.g., RUN apt-get update) in a Dockerfile without a subsequent '\
       'install command creates cached layers that can contain outdated package indexes.'

  tag cis: 'CIS-Docker-4.7'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  # Check all Dockerfiles in standard locations
  dockerfiles = command('find / -name "Dockerfile" -not -path "*/\\.git/*" 2>/dev/null').stdout.strip.split("\n")

  if dockerfiles.empty?
    describe 'Dockerfiles' do
      skip 'No Dockerfiles found on the system'
    end
  else
    dockerfiles.each do |dockerfile|
      describe file(dockerfile) do
        its('content') { should_not match /^RUN\s+(apt-get update|yum update|apk update)\s*$/ }
      end
    end
  end
end

# CIS 4.8: Ensure setuid and setgid permissions are removed
control 'cis-docker-4-8' do
  impact 0.5
  title 'Ensure setuid and setgid permissions are removed in the images'
  desc 'Removing setuid and setgid permissions in container images prevents privilege escalation attacks.'

  tag cis: 'CIS-Docker-4.8'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  describe 'Setuid/setgid permissions in containers' do
    skip 'Manual review required: Run "find / -perm +6000 -type f" within containers '\
         'to identify files with setuid/setgid bits and remove them where not needed.'
  end
end

# CIS 4.9: Ensure that COPY is used instead of ADD in Dockerfiles
control 'cis-docker-4-9' do
  impact 0.5
  title 'Ensure COPY is used instead of ADD in Dockerfiles'
  desc 'COPY should be used instead of ADD in Dockerfiles. ADD has extra features '\
       '(like local tar file auto-extraction and remote URL support) that could introduce vulnerabilities.'

  tag cis: 'CIS-Docker-4.9'
  tag severity: 'medium'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  dockerfiles = command('find / -name "Dockerfile" -not -path "*/\\.git/*" 2>/dev/null').stdout.strip.split("\n")

  if dockerfiles.empty?
    describe 'Dockerfiles' do
      skip 'No Dockerfiles found on the system'
    end
  else
    dockerfiles.each do |dockerfile|
      describe file(dockerfile) do
        # ADD should not be used for local file copies (allow ADD for URLs when necessary)
        its('content') { should_not match /^ADD\s+(?!http|https|ftp)/ }
      end
    end
  end
end

# CIS 4.10: Ensure secrets are not stored in Dockerfiles
control 'cis-docker-4-10' do
  impact 0.9
  title 'Ensure secrets are not stored in Dockerfiles'
  desc 'Secrets such as passwords, API keys, and private keys should not be stored '\
       'in Dockerfiles as they could be exposed through image layers.'

  tag cis: 'CIS-Docker-4.10'
  tag severity: 'critical'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  dockerfiles = command('find / -name "Dockerfile" -not -path "*/\\.git/*" 2>/dev/null').stdout.strip.split("\n")

  if dockerfiles.empty?
    describe 'Dockerfiles' do
      skip 'No Dockerfiles found on the system'
    end
  else
    dockerfiles.each do |dockerfile|
      describe file(dockerfile) do
        # Check for common secret patterns
        its('content') { should_not match /ENV.*(PASSWORD|SECRET|KEY|TOKEN|PASSWD)\s*=\s*\S+/i }
        its('content') { should_not match /ARG.*(PASSWORD|SECRET|KEY|TOKEN|PASSWD)\s*=\s*\S+/i }
      end
    end
  end
end

# CIS 4.11: Ensure only necessary ports are open on the container
control 'cis-docker-4-11' do
  impact 0.7
  title 'Ensure only necessary ports are open on the container'
  desc 'Containers should only expose the ports that are required for their function. '\
       'Exposing unnecessary ports increases the attack surface.'

  tag cis: 'CIS-Docker-4.11'
  tag severity: 'high'
  tag standard: 'CIS Docker Benchmark v1.6.0'

  running_containers = command('docker ps --quiet 2>/dev/null').stdout.strip.split("\n")

  if running_containers.empty?
    describe 'Running containers' do
      skip 'No running containers found'
    end
  else
    describe 'Container port exposure' do
      skip 'Manual review required: Verify that each running container only exposes necessary ports. '\
           'Run "docker port <container_id>" to review exposed ports.'
    end
  end
end
