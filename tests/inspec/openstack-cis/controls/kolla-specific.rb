# CIS OpenStack Benchmark - Kolla-Ansible Specific Controls
# These controls are adapted for Kolla containerized deployments

# Kolla deploys OpenStack services in Docker containers
# Config files are on host at /etc/kolla/<service>/
# Containers mount these and read from /var/lib/kolla/config_files/

control 'kolla-1.1' do
  impact 1.0
  title 'Ensure Kolla config directory has correct permissions'
  desc 'The /etc/kolla directory should be protected'
  
  describe directory('/etc/kolla') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('mode') { should cmp <= '0755' }
  end
end

control 'kolla-1.2' do
  impact 1.0
  title 'Ensure Keystone container config has correct permissions'
  desc 'Keystone configuration should be protected'
  
  describe file('/etc/kolla/keystone/keystone.conf') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('mode') { should cmp <= '0640' }
  end
end

control 'kolla-1.3' do
  impact 0.7
  title 'Ensure Keystone uses Fernet tokens'
  desc 'Fernet tokens are recommended for security'
  
  describe ini('/etc/kolla/keystone/keystone.conf') do
    its(['token', 'provider']) { should match(/fernet/i) }
  end
end

control 'kolla-1.4' do
  impact 0.7
  title 'Ensure token expiration is configured'
  desc 'Tokens should expire within a reasonable time'
  
  describe ini('/etc/kolla/keystone/keystone.conf') do
    its(['token', 'expiration']) { should cmp <= 3600 }
  end
end

control 'kolla-2.1' do
  impact 1.0
  title 'Ensure Nova API config has correct permissions'
  desc 'Nova API configuration should be protected'
  
  describe file('/etc/kolla/nova-api/nova.conf') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('mode') { should cmp <= '0640' }
  end
end

control 'kolla-2.2' do
  impact 1.0
  title 'Ensure Nova Compute config has correct permissions'
  desc 'Nova Compute configuration should be protected'
  
  only_if('Nova Compute is installed') do
    file('/etc/kolla/nova-compute/nova.conf').exist?
  end
  
  describe file('/etc/kolla/nova-compute/nova.conf') do
    its('owner') { should eq 'root' }
    its('mode') { should cmp <= '0640' }
  end
end

control 'kolla-3.1' do
  impact 1.0
  title 'Ensure Neutron config has correct permissions'
  desc 'Neutron configuration should be protected'
  
  describe file('/etc/kolla/neutron-server/neutron.conf') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('mode') { should cmp <= '0640' }
  end
end

control 'kolla-3.2' do
  impact 0.7
  title 'Ensure Neutron uses Keystone auth'
  desc 'Neutron should authenticate via Keystone'
  
  describe ini('/etc/kolla/neutron-server/neutron.conf') do
    its(['DEFAULT', 'auth_strategy']) { should eq 'keystone' }
  end
end

control 'kolla-4.1' do
  impact 1.0
  title 'Ensure Glance config has correct permissions'
  desc 'Glance configuration should be protected'
  
  describe file('/etc/kolla/glance-api/glance-api.conf') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('mode') { should cmp <= '0640' }
  end
end

control 'kolla-5.1' do
  impact 1.0
  title 'Ensure Heat config has correct permissions'
  desc 'Heat configuration should be protected'
  
  only_if('Heat is installed') do
    file('/etc/kolla/heat-api/heat.conf').exist?
  end
  
  describe file('/etc/kolla/heat-api/heat.conf') do
    its('owner') { should eq 'root' }
    its('mode') { should cmp <= '0640' }
  end
end

control 'kolla-5.2' do
  impact 0.7
  title 'Ensure Heat uses trusts for deferred auth'
  desc 'Trusts are the recommended deferred auth method'
  
  only_if('Heat is installed') do
    file('/etc/kolla/heat-api/heat.conf').exist?
  end
  
  describe ini('/etc/kolla/heat-api/heat.conf') do
    its(['DEFAULT', 'deferred_auth_method']) { should eq 'trusts' }
  end
end

control 'kolla-6.1' do
  impact 1.0
  title 'Ensure Horizon config has correct permissions'
  desc 'Horizon configuration should be protected'
  
  describe file('/etc/kolla/horizon/local_settings') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('mode') { should cmp <= '0640' }
  end
end

control 'kolla-6.2' do
  impact 0.7
  title 'Ensure Horizon DEBUG is disabled'
  desc 'DEBUG mode should be disabled in production'
  
  describe file('/etc/kolla/horizon/local_settings') do
    its('content') { should match(/DEBUG\s*=\s*False/) }
  end
end

control 'kolla-7.1' do
  impact 1.0
  title 'Ensure Docker containers are running'
  desc 'All Kolla containers should be running'
  
  %w[
    keystone
    nova_api
    nova_conductor
    nova_scheduler
    neutron_server
    glance_api
    placement_api
    horizon
  ].each do |container|
    describe docker_container(container) do
      it { should exist }
      it { should be_running }
    end
  end
end

control 'kolla-7.2' do
  impact 0.7
  title 'Ensure HAProxy is running for HA'
  desc 'HAProxy should be running for high availability'
  
  describe docker_container('haproxy') do
    it { should exist }
    it { should be_running }
  end
end

control 'kolla-7.3' do
  impact 0.7
  title 'Ensure MariaDB is running'
  desc 'Database service should be running'
  
  describe docker_container('mariadb') do
    it { should exist }
    it { should be_running }
  end
end

control 'kolla-7.4' do
  impact 0.7
  title 'Ensure RabbitMQ is running'
  desc 'Message queue service should be running'
  
  describe docker_container('rabbitmq') do
    it { should exist }
    it { should be_running }
  end
end

control 'kolla-8.1' do
  impact 1.0
  title 'Ensure passwords.yml is protected'
  desc 'Kolla passwords file contains sensitive data'
  
  describe file('/etc/kolla/passwords.yml') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('mode') { should cmp <= '0600' }
  end
end

control 'kolla-8.2' do
  impact 1.0
  title 'Ensure globals.yml is protected'
  desc 'Kolla globals file contains deployment config'
  
  describe file('/etc/kolla/globals.yml') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('mode') { should cmp <= '0640' }
  end
end
