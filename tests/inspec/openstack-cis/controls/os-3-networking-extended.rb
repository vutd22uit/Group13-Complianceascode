# Extended Neutron Networking Security Controls
# CIS OpenStack Benchmark - Extended Networking Checks

control 'os-networking-3.5' do
  title 'Ensure ML2 plugin uses secure drivers'
  desc 'ML2 plugin should use appropriate network drivers.'
  impact 0.7
  refs 'CIS OpenStack Benchmark', version: '1.0', section: '3.5'
  
  describe ini('/etc/neutron/plugins/ml2/ml2_conf.ini') do
    its(['ml2', 'mechanism_drivers']) { should_not be_nil }
  end
end

control 'os-networking-3.6' do
  title 'Ensure DHCP agent is properly secured'
  desc 'DHCP agent configuration should be protected.'
  impact 0.7
  
  describe file('/etc/neutron/dhcp_agent.ini') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'neutron' }
    its('mode') { should cmp <= 0640 }
  end
end

control 'os-networking-3.7' do
  title 'Ensure L3 agent uses namespaces'
  desc 'Network namespaces provide isolation between tenants.'
  impact 1.0
  
  describe ini('/etc/neutron/l3_agent.ini') do
    its(['DEFAULT', 'use_namespaces']) { should eq 'true' }
  end
end

control 'os-networking-3.8' do
  title 'Ensure metadata agent uses secure proxy'
  desc 'Metadata agent should properly secure metadata access.'
  impact 0.8
  
  describe file('/etc/neutron/metadata_agent.ini') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'neutron' }
    its('mode') { should cmp <= 0640 }
  end
  
  describe ini('/etc/neutron/metadata_agent.ini') do
    its(['DEFAULT', 'metadata_proxy_shared_secret']) { should_not be_nil }
  end
end
