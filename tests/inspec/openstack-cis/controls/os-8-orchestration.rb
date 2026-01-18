# OpenStack Heat (Orchestration) Security Controls
# CIS OpenStack Benchmark

control 'os-orchestration-8.1' do
  title 'Ensure heat.conf has correct ownership'
  desc 'Heat configuration files should be protected.'
  impact 1.0
  refs 'CIS OpenStack Benchmark', version: '1.0', section: '8.1'
  
  describe file('/etc/heat/heat.conf') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'heat' }
    its('mode') { should cmp <= 0640 }
  end
end

control 'os-orchestration-8.2' do
  title 'Ensure Heat API uses SSL'
  desc 'Heat API should be served over HTTPS.'
  impact 1.0
  
  describe ini('/etc/heat/heat.conf') do
    its(['heat_api', 'use_ssl']) { should eq 'true' }
  end
end

control 'os-orchestration-8.3' do
  title 'Ensure Heat uses Keystone authentication'
  desc 'Heat should delegate authentication to Keystone.'
  impact 1.0
  
  describe ini('/etc/heat/heat.conf') do
    its(['keystone_authtoken', 'auth_type']) { should eq 'password' }
  end
end

control 'os-orchestration-8.4' do
  title 'Ensure stack domain is properly configured'
  desc 'Heat should use a dedicated domain for stack resources.'
  impact 0.7
  
  describe ini('/etc/heat/heat.conf') do
    its(['DEFAULT', 'stack_domain_admin']) { should_not be_nil }
    its(['DEFAULT', 'stack_user_domain_name']) { should_not be_nil }
  end
end

control 'os-orchestration-8.5' do
  title 'Ensure deferred_auth_method is trusts'
  desc 'Heat should use trusts for deferred authentication.'
  impact 0.8
  
  describe ini('/etc/heat/heat.conf') do
    its(['DEFAULT', 'deferred_auth_method']) { should eq 'trusts' }
  end
end
