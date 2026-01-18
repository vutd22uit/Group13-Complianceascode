# CIS Linux Benchmark - Section 1: Initial Setup
# InSpec Controls

# ============================================================================
# 1.1 Filesystem Configuration
# ============================================================================

# CIS 1.1.1.1: Disable cramfs
control 'cis-linux-1-1-1-1' do
  impact 0.5
  title 'Ensure mounting of cramfs filesystems is disabled'
  desc 'The cramfs filesystem type is a compressed read-only Linux filesystem.'

  tag cis: 'CIS-Linux-1.1.1.1'
  tag severity: 'medium'
  tag standard: 'CIS Linux Benchmark'

  describe kernel_module('cramfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end

  describe file('/etc/modprobe.d/cramfs.conf') do
    it { should exist }
    its('content') { should match /install cramfs \/bin\/true/ }
  end
end

# CIS 1.1.1.2: Disable freevxfs
control 'cis-linux-1-1-1-2' do
  impact 0.5
  title 'Ensure mounting of freevxfs filesystems is disabled'
  desc 'The freevxfs filesystem type is a free version of the Veritas type filesystem.'

  tag cis: 'CIS-Linux-1.1.1.2'
  tag severity: 'medium'

  describe kernel_module('freevxfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

# CIS 1.1.1.3: Disable jffs2
control 'cis-linux-1-1-1-3' do
  impact 0.5
  title 'Ensure mounting of jffs2 filesystems is disabled'
  desc 'The jffs2 filesystem type is a log-structured filesystem used in flash memory devices.'

  tag cis: 'CIS-Linux-1.1.1.3'
  tag severity: 'medium'

  describe kernel_module('jffs2') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

# CIS 1.1.1.4: Disable hfs
control 'cis-linux-1-1-1-4' do
  impact 0.5
  title 'Ensure mounting of hfs filesystems is disabled'
  desc 'The hfs filesystem type is a hierarchical filesystem.'

  tag cis: 'CIS-Linux-1.1.1.4'
  tag severity: 'medium'

  describe kernel_module('hfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

# CIS 1.1.1.5: Disable hfsplus
control 'cis-linux-1-1-1-5' do
  impact 0.5
  title 'Ensure mounting of hfsplus filesystems is disabled'
  desc 'The hfsplus filesystem type is a hierarchical filesystem.'

  tag cis: 'CIS-Linux-1.1.1.5'
  tag severity: 'medium'

  describe kernel_module('hfsplus') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

# CIS 1.1.1.6: Disable udf
control 'cis-linux-1-1-1-6' do
  impact 0.5
  title 'Ensure mounting of udf filesystems is disabled'
  desc 'The udf filesystem type is the universal disk format.'

  tag cis: 'CIS-Linux-1.1.1.6'
  tag severity: 'medium'

  describe kernel_module('udf') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

# CIS 1.1.2: Ensure /tmp is configured
control 'cis-linux-1-1-2' do
  impact 0.7
  title 'Ensure /tmp is configured'
  desc '/tmp should be a separate partition with noexec, nosuid, nodev options.'

  tag cis: 'CIS-Linux-1.1.2'
  tag severity: 'high'

  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
    its('options') { should include 'nodev' }
    its('options') { should include 'noexec' }
  end
end

# CIS 1.1.8: Ensure /var/tmp is configured
control 'cis-linux-1-1-8' do
  impact 0.7
  title 'Ensure /var/tmp is configured'
  desc '/var/tmp should have noexec, nosuid, nodev options.'

  tag cis: 'CIS-Linux-1.1.8'
  tag severity: 'high'

  describe mount('/var/tmp') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
    its('options') { should include 'nodev' }
    its('options') { should include 'noexec' }
  end
end

# ============================================================================
# 1.3 Filesystem Integrity
# ============================================================================

# CIS 1.3.1: Ensure AIDE is installed
control 'cis-linux-1-3-1' do
  impact 0.7
  title 'Ensure AIDE is installed'
  desc 'AIDE takes a snapshot of filesystem state including modification times, permissions, and file hashes.'

  tag cis: 'CIS-Linux-1.3.1'
  tag severity: 'high'

  only_if('AIDE is expected to be installed') do
    !virtualization.container?
  end

  describe.one do
    describe package('aide') do
      it { should be_installed }
    end
    describe package('aide-common') do
      it { should be_installed }
    end
  end
end

# CIS 1.3.2: Ensure filesystem integrity is regularly checked
control 'cis-linux-1-3-2' do
  impact 0.7
  title 'Ensure filesystem integrity is regularly checked'
  desc 'File system integrity checking should be scheduled via cron or systemd timer.'

  tag cis: 'CIS-Linux-1.3.2'
  tag severity: 'high'

  describe.one do
    describe crontab do
      its('commands') { should include /aide/ }
    end
    describe systemd_service('aidecheck.timer') do
      it { should be_enabled }
      it { should be_running }
    end
    describe file('/etc/cron.daily/aide') do
      it { should exist }
    end
  end
end

# ============================================================================
# 1.4 Secure Boot Settings
# ============================================================================

# CIS 1.4.1: Ensure bootloader password is set
control 'cis-linux-1-4-1' do
  impact 0.7
  title 'Ensure bootloader password is set'
  desc 'Setting the boot loader password protects the system from unauthorized access.'

  tag cis: 'CIS-Linux-1.4.1'
  tag severity: 'high'

  grub_files = [
    '/boot/grub2/grub.cfg',
    '/boot/grub/grub.cfg',
    '/boot/grub2/user.cfg'
  ]

  only_if('System uses GRUB bootloader') do
    grub_files.any? { |f| file(f).exist? }
  end

  describe.one do
    grub_files.each do |grub_file|
      describe file(grub_file) do
        its('content') { should match /password_pbkdf2|set superusers/ }
      end
    end
  end
end

# CIS 1.4.2: Ensure permissions on bootloader config are configured
control 'cis-linux-1-4-2' do
  impact 0.7
  title 'Ensure permissions on bootloader config are configured'
  desc 'The grub configuration file should be owned by root with permissions 600.'

  tag cis: 'CIS-Linux-1.4.2'
  tag severity: 'high'

  grub_files = ['/boot/grub2/grub.cfg', '/boot/grub/grub.cfg']

  grub_files.each do |grub_file|
    next unless file(grub_file).exist?

    describe file(grub_file) do
      its('owner') { should eq 'root' }
      its('group') { should eq 'root' }
      its('mode') { should cmp '0600' }
    end
  end
end

# ============================================================================
# 1.5 Additional Process Hardening
# ============================================================================

# CIS 1.5.1: Ensure core dumps are restricted
control 'cis-linux-1-5-1' do
  impact 0.5
  title 'Ensure core dumps are restricted'
  desc 'Core dumps can contain sensitive data and should be restricted.'

  tag cis: 'CIS-Linux-1.5.1'
  tag severity: 'medium'

  describe limits_conf('/etc/security/limits.conf') do
    its('*') { should include ['hard', 'core', '0'] }
  end

  describe kernel_parameter('fs.suid_dumpable') do
    its('value') { should eq 0 }
  end

  describe systemd_service('coredump.socket') do
    it { should_not be_enabled }
  end if systemd_service('coredump.socket').exist?
end

# CIS 1.5.2: Ensure XD/NX support is enabled
control 'cis-linux-1-5-2' do
  impact 0.7
  title 'Ensure XD/NX support is enabled'
  desc 'Execute Disable (XD) prevents code execution from data memory pages.'

  tag cis: 'CIS-Linux-1.5.2'
  tag severity: 'high'

  describe command('dmesg | grep -E "NX|XD"') do
    its('stdout') { should match /NX \(Execute Disable\) protection: active/ }
  end
end

# CIS 1.5.3: Ensure ASLR is enabled
control 'cis-linux-1-5-3' do
  impact 0.7
  title 'Ensure address space layout randomization (ASLR) is enabled'
  desc 'ASLR is an exploit mitigation technique.'

  tag cis: 'CIS-Linux-1.5.3'
  tag severity: 'high'

  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should eq 2 }
  end
end

# CIS 1.5.4: Ensure prelink is disabled
control 'cis-linux-1-5-4' do
  impact 0.5
  title 'Ensure prelink is not installed'
  desc 'Prelink can interfere with AIDE and should not be used.'

  tag cis: 'CIS-Linux-1.5.4'
  tag severity: 'medium'

  describe package('prelink') do
    it { should_not be_installed }
  end
end

# ============================================================================
# 1.6 Mandatory Access Control
# ============================================================================

# CIS 1.6.1.1: Ensure SELinux is installed (RHEL/CentOS)
control 'cis-linux-1-6-1-1' do
  impact 0.7
  title 'Ensure SELinux is installed'
  desc 'SELinux provides Mandatory Access Controls.'

  tag cis: 'CIS-Linux-1.6.1.1'
  tag severity: 'high'

  only_if('System uses SELinux') do
    os.redhat? || os.family == 'fedora'
  end

  describe package('libselinux') do
    it { should be_installed }
  end
end

# CIS 1.6.1.2: Ensure SELinux is not disabled in bootloader
control 'cis-linux-1-6-1-2' do
  impact 0.7
  title 'Ensure SELinux is not disabled in bootloader configuration'
  desc 'SELinux should not be disabled in GRUB configuration.'

  tag cis: 'CIS-Linux-1.6.1.2'
  tag severity: 'high'

  only_if('System uses SELinux') do
    os.redhat? || os.family == 'fedora'
  end

  describe file('/etc/default/grub') do
    its('content') { should_not match /selinux=0/ }
    its('content') { should_not match /enforcing=0/ }
  end
end

# CIS 1.6.1.3: Ensure SELinux policy is configured
control 'cis-linux-1-6-1-3' do
  impact 0.7
  title 'Ensure SELinux policy is configured'
  desc 'SELinux policy should be set to targeted or mls.'

  tag cis: 'CIS-Linux-1.6.1.3'
  tag severity: 'high'

  only_if('System uses SELinux') do
    os.redhat? || os.family == 'fedora'
  end

  describe parse_config_file('/etc/selinux/config') do
    its('SELINUXTYPE') { should match /targeted|mls/ }
  end
end

# CIS 1.6.1.4: Ensure SELinux mode is enforcing
control 'cis-linux-1-6-1-4' do
  impact 0.7
  title 'Ensure SELinux mode is enforcing or permissive'
  desc 'SELinux should be in enforcing mode.'

  tag cis: 'CIS-Linux-1.6.1.4'
  tag severity: 'high'

  only_if('System uses SELinux') do
    os.redhat? || os.family == 'fedora'
  end

  describe parse_config_file('/etc/selinux/config') do
    its('SELINUX') { should eq 'enforcing' }
  end

  describe command('getenforce') do
    its('stdout') { should match /Enforcing/ }
  end
end

# ============================================================================
# 1.7 Command Line Warning Banners
# ============================================================================

# CIS 1.7.1: Ensure message of the day is configured properly
control 'cis-linux-1-7-1' do
  impact 0.3
  title 'Ensure message of the day is configured properly'
  desc 'The login banner should not contain OS information.'

  tag cis: 'CIS-Linux-1.7.1'
  tag severity: 'low'

  describe file('/etc/motd') do
    it { should exist }
    its('content') { should_not match /\\v|\\r|\\m|\\s/ }
  end
end

# CIS 1.7.2: Ensure local login warning banner is configured
control 'cis-linux-1-7-2' do
  impact 0.3
  title 'Ensure local login warning banner is configured properly'
  desc '/etc/issue should contain appropriate warning.'

  tag cis: 'CIS-Linux-1.7.2'
  tag severity: 'low'

  describe file('/etc/issue') do
    it { should exist }
    its('content') { should_not match /\\v|\\r|\\m|\\s/ }
    its('content') { should match /Authorized users only/ }
  end
end

# CIS 1.7.3: Ensure remote login warning banner is configured
control 'cis-linux-1-7-3' do
  impact 0.3
  title 'Ensure remote login warning banner is configured properly'
  desc '/etc/issue.net should contain appropriate warning.'

  tag cis: 'CIS-Linux-1.7.3'
  tag severity: 'low'

  describe file('/etc/issue.net') do
    it { should exist }
    its('content') { should_not match /\\v|\\r|\\m|\\s/ }
    its('content') { should match /Authorized users only/ }
  end
end

# CIS 1.7.4: Ensure permissions on /etc/motd are configured
control 'cis-linux-1-7-4' do
  impact 0.3
  title 'Ensure permissions on /etc/motd are configured'
  desc '/etc/motd should be owned by root.'

  tag cis: 'CIS-Linux-1.7.4'
  tag severity: 'low'

  describe file('/etc/motd') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end if file('/etc/motd').exist?
end

# CIS 1.7.5: Ensure permissions on /etc/issue are configured
control 'cis-linux-1-7-5' do
  impact 0.3
  title 'Ensure permissions on /etc/issue are configured'
  desc '/etc/issue should be owned by root.'

  tag cis: 'CIS-Linux-1.7.5'
  tag severity: 'low'

  describe file('/etc/issue') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end

# CIS 1.7.6: Ensure permissions on /etc/issue.net are configured
control 'cis-linux-1-7-6' do
  impact 0.3
  title 'Ensure permissions on /etc/issue.net are configured'
  desc '/etc/issue.net should be owned by root.'

  tag cis: 'CIS-Linux-1.7.6'
  tag severity: 'low'

  describe file('/etc/issue.net') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end
