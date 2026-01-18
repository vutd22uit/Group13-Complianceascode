# CIS Linux Benchmark - Section 4: Logging and Auditing
# InSpec Controls

# CIS 4.1.1.1: Ensure auditd is installed
control 'cis-linux-4-1-1-1' do
  impact 0.7
  title 'Ensure auditd is installed'
  desc 'auditd is the userspace component to the Linux Auditing System.'
  tag cis: 'CIS-Linux-4.1.1.1'
  tag severity: 'high'

  describe.one do
    describe package('auditd') do
      it { should be_installed }
    end
    describe package('audit') do
      it { should be_installed }
    end
  end
end

# CIS 4.1.1.2: Ensure auditd service is enabled
control 'cis-linux-4-1-1-2' do
  impact 0.7
  title 'Ensure auditd service is enabled'
  tag cis: 'CIS-Linux-4.1.1.2'
  tag severity: 'high'

  describe service('auditd') do
    it { should be_enabled }
    it { should be_running }
  end
end

# CIS 4.1.1.3: Ensure auditing for processes starting prior to auditd
control 'cis-linux-4-1-1-3' do
  impact 0.7
  title 'Ensure auditing for processes that start prior to auditd is enabled'
  tag cis: 'CIS-Linux-4.1.1.3'
  tag severity: 'high'

  describe file('/etc/default/grub') do
    its('content') { should match /audit=1/ }
  end
end

# CIS 4.1.2: Ensure audit log storage size is configured
control 'cis-linux-4-1-2' do
  impact 0.5
  title 'Ensure audit log storage size is configured'
  tag cis: 'CIS-Linux-4.1.2'
  tag severity: 'medium'

  describe auditd_conf do
    its('max_log_file') { should cmp >= 8 }
  end
end

# CIS 4.1.17: Ensure the audit configuration is immutable
control 'cis-linux-4-1-17' do
  impact 0.7
  title 'Ensure the audit configuration is immutable'
  tag cis: 'CIS-Linux-4.1.17'
  tag severity: 'high'

  describe auditd do
    its('lines') { should include '-e 2' }
  end
end

# CIS 4.2.1.1: Ensure rsyslog is installed
control 'cis-linux-4-2-1-1' do
  impact 0.7
  title 'Ensure rsyslog is installed'
  tag cis: 'CIS-Linux-4.2.1.1'
  tag severity: 'high'

  describe.one do
    describe package('rsyslog') do
      it { should be_installed }
    end
    describe package('syslog-ng') do
      it { should be_installed }
    end
  end
end

# CIS 4.2.1.2: Ensure rsyslog service is enabled
control 'cis-linux-4-2-1-2' do
  impact 0.7
  title 'Ensure rsyslog service is enabled'
  tag cis: 'CIS-Linux-4.2.1.2'
  tag severity: 'high'

  describe service('rsyslog') do
    it { should be_enabled }
    it { should be_running }
  end
end

# CIS 4.2.3: Ensure permissions on logfiles are configured
control 'cis-linux-4-2-3' do
  impact 0.5
  title 'Ensure permissions on all logfiles are configured'
  tag cis: 'CIS-Linux-4.2.3'
  tag severity: 'medium'

  log_files = command('find /var/log -type f -perm /137').stdout.split("\n")

  describe 'Log files with excessive permissions' do
    subject { log_files }
    its('count') { should eq 0 }
  end
end
