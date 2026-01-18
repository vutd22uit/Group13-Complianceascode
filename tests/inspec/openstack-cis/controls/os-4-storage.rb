control 'os-storage-4.1' do
  title 'Ensure cinder.conf ownership is set to root:cinder'
  desc 'The cinder.conf file contains sensitive configuration information. It should be owned by root and the cinder group.'
  impact 1.0
  refs 'CIS OpenStack Benchmark', version: '1.0', section: '4.1'
  
  describe file('/etc/cinder/cinder.conf') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'cinder' }
  end
end

control 'os-storage-4.2' do
  title 'Ensure cinder.conf permissions are set to 640 or stricter'
  desc 'The cinder.conf file should be readable by root and the cinder group only.'
  impact 1.0
  
  describe file('/etc/cinder/cinder.conf') do
    it { should exist }
    its('mode') { should cmp <= 0640 }
  end
end

control 'os-storage-4.3' do
  title 'Ensure NAS secure file permissions'
  desc 'If using NAS for Cinder backend, ensure file permissions are restrictive.'
  impact 0.8
  
  describe ini('/etc/cinder/cinder.conf') do
    its(['DEFAULT', 'nas_secure_file_permissions']) { should eq 'auto' }
    its(['DEFAULT', 'nas_secure_file_operations']) { should eq 'auto' }
  end
end

control 'os-storage-4.4' do
  title 'Ensure swift.conf hash path prefix/suffix are unique'
  desc 'Swift hash path prefix and suffix should be set to prevent hash collision attacks.'
  impact 1.0
  
  describe ini('/etc/swift/swift.conf') do
    its(['swift-hash', 'swift_hash_path_prefix']) { should_not eq 'changeme' }
    its(['swift-hash', 'swift_hash_path_suffix']) { should_not eq 'changeme' }
  end
end
