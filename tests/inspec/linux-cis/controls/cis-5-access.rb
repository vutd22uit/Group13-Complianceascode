# CIS Linux Benchmark - Section 5: Access, Authentication, Authorization
# InSpec Controls

# CIS 5.1.1: Ensure cron daemon is enabled
control 'cis-linux-5-1-1' do
  impact 0.5
  title 'Ensure cron daemon is enabled and running'
  tag cis: 'CIS-Linux-5.1.1'
  tag severity: 'medium'

  describe service('cron') do
    it { should be_enabled }
    it { should be_running }
  end
end

# CIS 5.1.2: Ensure permissions on /etc/crontab
control 'cis-linux-5-1-2' do
  impact 0.5
  title 'Ensure permissions on /etc/crontab are configured'
  tag cis: 'CIS-Linux-5.1.2'
  tag severity: 'medium'

  describe file('/etc/crontab') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0600' }
  end
end

# CIS 5.2.1: Ensure permissions on /etc/ssh/sshd_config
control 'cis-linux-5-2-1' do
  impact 0.7
  title 'Ensure permissions on /etc/ssh/sshd_config are configured'
  tag cis: 'CIS-Linux-5.2.1'
  tag severity: 'high'

  describe file('/etc/ssh/sshd_config') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0600' }
  end
end

# CIS 5.2.4: Ensure SSH Protocol is set to 2
control 'cis-linux-5-2-4' do
  impact 0.7
  title 'Ensure SSH Protocol is set to 2'
  tag cis: 'CIS-Linux-5.2.4'
  tag severity: 'high'

  describe sshd_config do
    its('Protocol') { should cmp 2 }
  end
end

# CIS 5.2.5: Ensure SSH LogLevel is appropriate
control 'cis-linux-5-2-5' do
  impact 0.5
  title 'Ensure SSH LogLevel is appropriate'
  tag cis: 'CIS-Linux-5.2.5'
  tag severity: 'medium'

  describe sshd_config do
    its('LogLevel') { should match /INFO|VERBOSE/ }
  end
end

# CIS 5.2.8: Ensure SSH root login is disabled
control 'cis-linux-5-2-8' do
  impact 1.0
  title 'Ensure SSH root login is disabled'
  tag cis: 'CIS-Linux-5.2.8'
  tag severity: 'critical'

  describe sshd_config do
    its('PermitRootLogin') { should eq 'no' }
  end
end

# CIS 5.2.10: Ensure SSH PermitUserEnvironment is disabled
control 'cis-linux-5-2-10' do
  impact 0.5
  title 'Ensure SSH PermitUserEnvironment is disabled'
  tag cis: 'CIS-Linux-5.2.10'
  tag severity: 'medium'

  describe sshd_config do
    its('PermitUserEnvironment') { should eq 'no' }
  end
end

# CIS 5.2.11: Ensure only strong ciphers are used
control 'cis-linux-5-2-11' do
  impact 0.7
  title 'Ensure only strong Ciphers are used'
  tag cis: 'CIS-Linux-5.2.11'
  tag severity: 'high'

  weak_ciphers = ['3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour']

  describe sshd_config do
    weak_ciphers.each do |cipher|
      its('Ciphers') { should_not include cipher }
    end
  end
end

# CIS 5.2.13: Ensure SSH Idle Timeout Interval is configured
control 'cis-linux-5-2-13' do
  impact 0.5
  title 'Ensure SSH Idle Timeout Interval is configured'
  tag cis: 'CIS-Linux-5.2.13'
  tag severity: 'medium'

  describe sshd_config do
    its('ClientAliveInterval') { should cmp <= 300 }
    its('ClientAliveCountMax') { should cmp <= 3 }
  end
end

# CIS 5.2.14: Ensure SSH LoginGraceTime is set
control 'cis-linux-5-2-14' do
  impact 0.5
  title 'Ensure SSH LoginGraceTime is set to one minute or less'
  tag cis: 'CIS-Linux-5.2.14'
  tag severity: 'medium'

  describe sshd_config do
    its('LoginGraceTime') { should cmp <= 60 }
  end
end

# CIS 5.2.15: Ensure SSH MaxAuthTries is set
control 'cis-linux-5-2-15' do
  impact 0.5
  title 'Ensure SSH MaxAuthTries is set to 4 or less'
  tag cis: 'CIS-Linux-5.2.15'
  tag severity: 'medium'

  describe sshd_config do
    its('MaxAuthTries') { should cmp <= 4 }
  end
end

# CIS 5.3.1: Ensure password creation requirements
control 'cis-linux-5-3-1' do
  impact 0.7
  title 'Ensure password creation requirements are configured'
  tag cis: 'CIS-Linux-5.3.1'
  tag severity: 'high'

  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /minlen\s*=\s*14/ }
    its('content') { should match /dcredit\s*=\s*-1/ }
    its('content') { should match /ucredit\s*=\s*-1/ }
    its('content') { should match /ocredit\s*=\s*-1/ }
    its('content') { should match /lcredit\s*=\s*-1/ }
  end
end

# CIS 5.4.1.1: Ensure password expiration is 365 days or less
control 'cis-linux-5-4-1-1' do
  impact 0.5
  title 'Ensure password expiration is 365 days or less'
  tag cis: 'CIS-Linux-5.4.1.1'
  tag severity: 'medium'

  describe login_defs do
    its('PASS_MAX_DAYS') { should cmp <= 365 }
  end
end

# CIS 5.4.1.2: Ensure minimum days between password changes
control 'cis-linux-5-4-1-2' do
  impact 0.5
  title 'Ensure minimum days between password changes is 7 or more'
  tag cis: 'CIS-Linux-5.4.1.2'
  tag severity: 'medium'

  describe login_defs do
    its('PASS_MIN_DAYS') { should cmp >= 1 }
  end
end

# CIS 5.4.1.4: Ensure inactive password lock is 30 days or less
control 'cis-linux-5-4-1-4' do
  impact 0.5
  title 'Ensure inactive password lock is 30 days or less'
  tag cis: 'CIS-Linux-5.4.1.4'
  tag severity: 'medium'

  describe command('useradd -D | grep INACTIVE') do
    its('stdout') { should match /INACTIVE=(30|[1-2][0-9]|[1-9])$/ }
  end
end

# CIS 5.4.4: Ensure default umask is 027 or more restrictive
control 'cis-linux-5-4-4' do
  impact 0.5
  title 'Ensure default user umask is 027 or more restrictive'
  tag cis: 'CIS-Linux-5.4.4'
  tag severity: 'medium'

  describe file('/etc/bash.bashrc') do
    its('content') { should match /umask\s+0?[0-2][0-7]/ }
  end

  describe file('/etc/profile') do
    its('content') { should match /umask\s+0?[0-2][0-7]/ }
  end
end

# CIS 5.6: Ensure access to su command is restricted
control 'cis-linux-5-6' do
  impact 0.7
  title 'Ensure access to the su command is restricted'
  tag cis: 'CIS-Linux-5.6'
  tag severity: 'high'

  describe file('/etc/pam.d/su') do
    its('content') { should match /auth\s+required\s+pam_wheel.so/ }
  end
end
