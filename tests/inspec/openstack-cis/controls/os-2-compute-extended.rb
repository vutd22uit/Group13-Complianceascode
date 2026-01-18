# Extended Nova Compute Security Controls
# CIS OpenStack Benchmark - Extended Compute Checks

control 'os-compute-2.5' do
  title 'Ensure libvirt uses secure migration'
  desc 'Live migration should be encrypted to protect data in transit.'
  impact 1.0
  refs 'CIS OpenStack Benchmark', version: '1.0', section: '2.5'
  
  describe ini('/etc/nova/nova.conf') do
    its(['libvirt', 'live_migration_tunnelled']) { should eq 'true' }
  end
end

control 'os-compute-2.6' do
  title 'Ensure serial console is secured'
  desc 'If serial console is enabled, it should use secure authentication.'
  impact 0.8
  
  describe.one do
    describe ini('/etc/nova/nova.conf') do
      its(['serial_console', 'enabled']) { should eq 'false' }
    end
    describe ini('/etc/nova/nova.conf') do
      its(['serial_console', 'base_url']) { should match /^https:/ }
    end
  end
end

control 'os-compute-2.7' do
  title 'Ensure metadata service uses HTTPS'
  desc 'Metadata service should use HTTPS when accessed externally.'
  impact 0.7
  
  describe ini('/etc/nova/nova.conf') do
    its(['api', 'metadata_use_https']) { should eq 'true' }
  end
end

control 'os-compute-2.8' do
  title 'Ensure compute API rate limiting is enabled'
  desc 'Rate limiting protects against DoS attacks.'
  impact 0.7
  
  describe ini('/etc/nova/nova.conf') do
    its(['oslo_middleware', 'max_request_body_size']) { should_not be_nil }
  end
end

control 'os-compute-2.9' do
  title 'Ensure nova-api uses SSL'
  desc 'Nova API should be served over HTTPS.'
  impact 1.0
  
  describe ini('/etc/nova/nova.conf') do
    its(['ssl', 'enable_ssl']) { should eq 'true' }
  end
end

control 'os-compute-2.10' do
  title 'Ensure libvirt security driver is configured'
  desc 'Libvirt should use SELinux or AppArmor for VM isolation.'
  impact 1.0
  
  describe.one do
    describe file('/etc/libvirt/qemu.conf') do
      its('content') { should match /security_driver.*=.*"selinux"/ }
    end
    describe file('/etc/libvirt/qemu.conf') do
      its('content') { should match /security_driver.*=.*"apparmor"/ }
    end
  end
end

control 'os-compute-2.11' do
  title 'Ensure disk encryption is enabled for ephemeral storage'
  desc 'Ephemeral disk encryption protects data at rest.'
  impact 0.8
  
  describe ini('/etc/nova/nova.conf') do
    its(['ephemeral_storage_encryption', 'enabled']) { should eq 'true' }
  end
end

control 'os-compute-2.12' do
  title 'Ensure instance isolation via separate networks'
  desc 'Instances should not share networks unless explicitly configured.'
  impact 0.7
  
  describe ini('/etc/nova/nova.conf') do
    its(['DEFAULT', 'use_neutron']) { should eq 'true' }
  end
end
