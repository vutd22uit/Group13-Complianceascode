# CIS Linux Benchmark - Section 6: System Maintenance
# InSpec Controls

# CIS 6.1.2: Ensure permissions on /etc/passwd
control 'cis-linux-6-1-2' do
  impact 0.7
  title 'Ensure permissions on /etc/passwd are configured'
  tag cis: 'CIS-Linux-6.1.2'
  tag severity: 'high'

  describe file('/etc/passwd') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end

# CIS 6.1.3: Ensure permissions on /etc/shadow
control 'cis-linux-6-1-3' do
  impact 1.0
  title 'Ensure permissions on /etc/shadow are configured'
  tag cis: 'CIS-Linux-6.1.3'
  tag severity: 'critical'

  describe file('/etc/shadow') do
    its('owner') { should eq 'root' }
    its('group') { should be_in ['root', 'shadow'] }
    its('mode') { should cmp '0640' }
  end
end

# CIS 6.1.4: Ensure permissions on /etc/group
control 'cis-linux-6-1-4' do
  impact 0.7
  title 'Ensure permissions on /etc/group are configured'
  tag cis: 'CIS-Linux-6.1.4'
  tag severity: 'high'

  describe file('/etc/group') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end

# CIS 6.1.5: Ensure permissions on /etc/gshadow
control 'cis-linux-6-1-5' do
  impact 0.7
  title 'Ensure permissions on /etc/gshadow are configured'
  tag cis: 'CIS-Linux-6.1.5'
  tag severity: 'high'

  describe file('/etc/gshadow') do
    its('owner') { should eq 'root' }
    its('group') { should be_in ['root', 'shadow'] }
    its('mode') { should cmp '0640' }
  end
end

# CIS 6.1.10: Ensure no world writable files exist
control 'cis-linux-6-1-10' do
  impact 0.7
  title 'Ensure no world writable files exist'
  tag cis: 'CIS-Linux-6.1.10'
  tag severity: 'high'

  world_writable = command('find / -xdev -type f -perm -0002 2>/dev/null').stdout.split("\n")

  describe 'World writable files' do
    subject { world_writable }
    its('count') { should eq 0 }
  end
end

# CIS 6.1.11: Ensure no unowned files or directories exist
control 'cis-linux-6-1-11' do
  impact 0.5
  title 'Ensure no unowned files or directories exist'
  tag cis: 'CIS-Linux-6.1.11'
  tag severity: 'medium'

  unowned = command('find / -xdev -nouser 2>/dev/null').stdout.split("\n")

  describe 'Unowned files' do
    subject { unowned }
    its('count') { should eq 0 }
  end
end

# CIS 6.1.12: Ensure no ungrouped files or directories exist
control 'cis-linux-6-1-12' do
  impact 0.5
  title 'Ensure no ungrouped files or directories exist'
  tag cis: 'CIS-Linux-6.1.12'
  tag severity: 'medium'

  ungrouped = command('find / -xdev -nogroup 2>/dev/null').stdout.split("\n")

  describe 'Ungrouped files' do
    subject { ungrouped }
    its('count') { should eq 0 }
  end
end

# CIS 6.2.1: Ensure password fields are not empty
control 'cis-linux-6-2-1' do
  impact 1.0
  title 'Ensure password fields are not empty'
  tag cis: 'CIS-Linux-6.2.1'
  tag severity: 'critical'

  describe shadow.where { password == '' } do
    its('users') { should be_empty }
  end
end

# CIS 6.2.2: Ensure no legacy "+" entries exist in /etc/passwd
control 'cis-linux-6-2-2' do
  impact 0.7
  title 'Ensure no legacy "+" entries exist in /etc/passwd'
  tag cis: 'CIS-Linux-6.2.2'
  tag severity: 'high'

  describe file('/etc/passwd') do
    its('content') { should_not match /^\+:/ }
  end
end

# CIS 6.2.6: Ensure root PATH Integrity
control 'cis-linux-6-2-6' do
  impact 0.7
  title 'Ensure root PATH Integrity'
  tag cis: 'CIS-Linux-6.2.6'
  tag severity: 'high'

  describe command("echo $PATH | tr ':' '\n' | grep -q '^\\.$' && echo 'Found'") do
    its('stdout') { should_not match /Found/ }
  end
end

# CIS 6.2.7: Ensure all users' home directories exist
control 'cis-linux-6-2-7' do
  impact 0.5
  title "Ensure all users' home directories exist"
  tag cis: 'CIS-Linux-6.2.7'
  tag severity: 'medium'

  passwd.where { uid >= 1000 && shell !~ /nologin|false/ }.homes.each do |home|
    describe file(home) do
      it { should exist }
      it { should be_directory }
    end
  end
end

# CIS 6.2.8: Ensure users' home directories permissions are 750 or more restrictive
control 'cis-linux-6-2-8' do
  impact 0.5
  title "Ensure users' home directories permissions are 750 or more restrictive"
  tag cis: 'CIS-Linux-6.2.8'
  tag severity: 'medium'

  passwd.where { uid >= 1000 && shell !~ /nologin|false/ }.homes.each do |home|
    next unless file(home).exist?

    describe file(home) do
      its('mode') { should cmp <= '0750' }
    end
  end
end

# CIS 6.2.9: Ensure users own their home directories
control 'cis-linux-6-2-9' do
  impact 0.5
  title 'Ensure users own their home directories'
  tag cis: 'CIS-Linux-6.2.9'
  tag severity: 'medium'

  passwd.where { uid >= 1000 && shell !~ /nologin|false/ }.each do |user|
    next unless file(user.home).exist?

    describe file(user.home) do
      its('owner') { should eq user.user }
    end
  end
end

# CIS 6.2.15: Ensure no duplicate UIDs exist
control 'cis-linux-6-2-15' do
  impact 0.7
  title 'Ensure no duplicate UIDs exist'
  tag cis: 'CIS-Linux-6.2.15'
  tag severity: 'high'

  uids = passwd.uids
  duplicate_uids = uids.select { |uid| uids.count(uid) > 1 }.uniq

  describe 'Duplicate UIDs' do
    subject { duplicate_uids }
    its('count') { should eq 0 }
  end
end

# CIS 6.2.16: Ensure no duplicate GIDs exist
control 'cis-linux-6-2-16' do
  impact 0.7
  title 'Ensure no duplicate GIDs exist'
  tag cis: 'CIS-Linux-6.2.16'
  tag severity: 'high'

  gids = etc_group.gids
  duplicate_gids = gids.select { |gid| gids.count(gid) > 1 }.uniq

  describe 'Duplicate GIDs' do
    subject { duplicate_gids }
    its('count') { should eq 0 }
  end
end

# CIS 6.2.17: Ensure no duplicate user names exist
control 'cis-linux-6-2-17' do
  impact 0.7
  title 'Ensure no duplicate user names exist'
  tag cis: 'CIS-Linux-6.2.17'
  tag severity: 'high'

  users = passwd.users
  duplicate_users = users.select { |user| users.count(user) > 1 }.uniq

  describe 'Duplicate users' do
    subject { duplicate_users }
    its('count') { should eq 0 }
  end
end
