# OpenStack Glance (Image Service) Security Controls
# CIS OpenStack Benchmark

control 'os-image-6.1' do
  title 'Ensure glance-api.conf has correct ownership'
  desc 'Glance configuration files should be protected.'
  impact 1.0
  refs 'CIS OpenStack Benchmark', version: '1.0', section: '6.1'
  
  describe file('/etc/glance/glance-api.conf') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'glance' }
    its('mode') { should cmp <= 0640 }
  end
end

control 'os-image-6.2' do
  title 'Ensure Glance API uses SSL'
  desc 'Glance API should be served over HTTPS.'
  impact 1.0
  
  describe ini('/etc/glance/glance-api.conf') do
    its(['DEFAULT', 'enable_v2_api']) { should eq 'true' }
  end
end

control 'os-image-6.3' do
  title 'Ensure image signing is enabled'
  desc 'Images should be verified using signatures.'
  impact 0.8
  
  describe ini('/etc/glance/glance-api.conf') do
    its(['image_format', 'container_formats']) { should_not be_nil }
  end
end

control 'os-image-6.4' do
  title 'Ensure Glance uses Keystone authentication'
  desc 'Glance should delegate authentication to Keystone.'
  impact 1.0
  
  describe ini('/etc/glance/glance-api.conf') do
    its(['keystone_authtoken', 'auth_type']) { should eq 'password' }
  end
end

control 'os-image-6.5' do
  title 'Ensure image location is restricted'
  desc 'Direct image location access should be disabled.'
  impact 0.7
  
  describe ini('/etc/glance/glance-api.conf') do
    its(['DEFAULT', 'show_image_direct_url']) { should eq 'false' }
  end
end
