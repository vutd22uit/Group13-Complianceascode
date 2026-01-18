control 'os-compute-2.1' do
  title 'Ensure nova.conf ownership is set to root:nova'
  desc 'The nova.conf file contains sensitive configuration information. It should be owned by root and the nova group.'
  impact 1.0
  refs 'CIS OpenStack Benchmark', version: '1.0', section: '2.1'
  
  describe file('/etc/nova/nova.conf') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'nova' }
  end
end

control 'os-compute-2.2' do
  title 'Ensure nova.conf permissions are set to 640 or stricter'
  desc 'The nova.conf file should be readable by root and the nova group only.'
  impact 1.0
  
  describe file('/etc/nova/nova.conf') do
    it { should exist }
    its('mode') { should cmp <= 0640 }
  end
end

control 'os-compute-2.3' do
  title 'Ensure VNC is using SSL'
  desc 'If VNC is enabled, it should strictly use SSL/TLS to encrypt console traffic.'
  impact 1.0
  
  describe.one do
    describe ini('/etc/nova/nova.conf') do
      its(['vnc', 'enabled']) { should eq 'false' }
    end
    describe ini('/etc/nova/nova.conf') do
      its(['vnc', 'novncproxy_host']) { should_not eq '0.0.0.0' }
      its(['vnc', 'auth_schemes']) { should include 'https' }
    end
  end
end

control 'os-compute-2.4' do
  title 'Ensure internal API communication is secure'
  desc 'Nova should communicate with other services over HTTPS.'
  impact 1.0

  describe ini('/etc/nova/nova.conf') do
    its(['glance', 'api_servers']) { should match /^https:/ }
    its(['neutron', 'auth_url']) { should match /^https:/ }
  end
end
