control 'os-identity-1.1' do
  title 'Ensure keystone.conf ownership is set to root:keystone'
  desc 'The keystone.conf file contains sensitive configuration information. It should be owned by root and the keystone group.'
  impact 1.0
  refs 'CIS OpenStack Benchmark', version: '1.0', section: '1.1'
  
  describe file('/etc/keystone/keystone.conf') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'keystone' }
  end
end

control 'os-identity-1.2' do
  title 'Ensure keystone.conf permissions are set to 640 or stricter'
  desc 'The keystone.conf file should be readable by root and the keystone group only.'
  impact 1.0
  
  describe file('/etc/keystone/keystone.conf') do
    it { should exist }
    its('mode') { should cmp <= 0640 }
  end
end

control 'os-identity-1.3' do
  title 'Ensure insecure TLS protocols are disabled'
  desc 'Keystone should not support old SSL/TLS versions.'
  impact 1.0
  
  describe ini('/etc/keystone/keystone.conf') do
    its(['ssl', 'enable_socket_ssl']) { should eq 'true' }
    its(['ssl', 'tls_version_min']) { should cmp >= '1.2' }
  end
end
