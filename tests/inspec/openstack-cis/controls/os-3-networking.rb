control 'os-networking-3.1' do
  title 'Ensure neutron.conf ownership is set to root:neutron'
  desc 'The neutron.conf file contains sensitive configuration information. It should be owned by root and the neutron group.'
  impact 1.0
  refs 'CIS OpenStack Benchmark', version: '1.0', section: '3.1'
  
  describe file('/etc/neutron/neutron.conf') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'neutron' }
  end
end

control 'os-networking-3.2' do
  title 'Ensure neutron.conf permissions are set to 640 or stricter'
  desc 'The neutron.conf file should be readable by root and the neutron group only.'
  impact 1.0
  
  describe file('/etc/neutron/neutron.conf') do
    it { should exist }
    its('mode') { should cmp <= 0640 }
  end
end

control 'os-networking-3.3' do
  title 'Ensure Neutron API uses SSL'
  desc 'Neutron API service should be configured to use SSL.'
  impact 1.0
  
  describe ini('/etc/neutron/neutron.conf') do
    its(['ssl', 'use_ssl']) { should eq 'true' }
  end
end

control 'os-networking-3.4' do
  title 'Ensure auth_strategy is set to keystone'
  desc 'Neutron should delegate authentication to Keystone.'
  impact 1.0

  describe ini('/etc/neutron/neutron.conf') do
    its(['DEFAULT', 'auth_strategy']) { should eq 'keystone' }
  end
end
