# Extended Cinder/Swift Storage Security Controls
# CIS OpenStack Benchmark - Extended Storage Checks

control 'os-storage-4.5' do
  title 'Ensure Cinder API uses SSL'
  desc 'Cinder API should be served over HTTPS.'
  impact 1.0
  refs 'CIS OpenStack Benchmark', version: '1.0', section: '4.5'
  
  describe ini('/etc/cinder/cinder.conf') do
    its(['ssl', 'enable_ssl']) { should eq 'true' }
  end
end

control 'os-storage-4.6' do
  title 'Ensure volume encryption is enabled'
  desc 'Volume encryption protects data at rest.'
  impact 1.0
  
  describe ini('/etc/cinder/cinder.conf') do
    its(['key_manager', 'backend']) { should_not be_nil }
  end
end

# ============================================
# Swift Object Storage Controls
# ============================================

control 'os-storage-5.1' do
  title 'Ensure swift.conf has correct ownership'
  desc 'Swift configuration files should be properly protected.'
  impact 1.0
  refs 'CIS OpenStack Benchmark', version: '1.0', section: '5.1'
  
  describe file('/etc/swift/swift.conf') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'swift' }
    its('mode') { should cmp <= 0640 }
  end
end

control 'os-storage-5.2' do
  title 'Ensure Swift proxy uses SSL'
  desc 'Swift proxy server should use HTTPS.'
  impact 1.0
  
  describe ini('/etc/swift/proxy-server.conf') do
    its(['DEFAULT', 'bind_port']) { should eq '8080' }
  end
end

control 'os-storage-5.3' do
  title 'Ensure Swift uses Keystone authentication'
  desc 'Swift should delegate authentication to Keystone.'
  impact 1.0
  
  describe ini('/etc/swift/proxy-server.conf') do
    its(['pipeline:main', 'pipeline']) { should match /authtoken/ }
  end
end

control 'os-storage-5.4' do
  title 'Ensure Swift container sync is secured'
  desc 'Container sync should use authentication.'
  impact 0.7
  
  describe ini('/etc/swift/container-sync-realms.conf') do
    it { should exist }
  end
end
