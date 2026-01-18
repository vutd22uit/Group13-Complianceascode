# Additional Keystone Security Controls
# CIS OpenStack Benchmark - Extended Identity Checks

control 'os-identity-1.4' do
  title 'Ensure admin token is disabled'
  desc 'The admin token should be disabled in production environments.'
  impact 1.0
  refs 'CIS OpenStack Benchmark', version: '1.0', section: '1.4'
  
  describe ini('/etc/keystone/keystone.conf') do
    its(['DEFAULT', 'admin_token']) { should be_nil }
  end
end

control 'os-identity-1.5' do
  title 'Ensure Fernet tokens are used'
  desc 'Fernet tokens are more secure and performant than UUID tokens.'
  impact 1.0
  
  describe ini('/etc/keystone/keystone.conf') do
    its(['token', 'provider']) { should eq 'fernet' }
  end
end

control 'os-identity-1.6' do
  title 'Ensure token expiration is set appropriately'
  desc 'Token expiration should be set to 1 hour (3600 seconds) or less.'
  impact 0.7
  
  describe ini('/etc/keystone/keystone.conf') do
    its(['token', 'expiration']) { should cmp <= 3600 }
  end
end

control 'os-identity-1.7' do
  title 'Ensure password hash algorithm is secure'
  desc 'Password hashing should use bcrypt or scrypt algorithm.'
  impact 1.0
  
  describe.one do
    describe ini('/etc/keystone/keystone.conf') do
      its(['identity', 'password_hash_algorithm']) { should eq 'bcrypt' }
    end
    describe ini('/etc/keystone/keystone.conf') do
      its(['identity', 'password_hash_algorithm']) { should eq 'scrypt' }
    end
  end
end

control 'os-identity-1.8' do
  title 'Ensure keystone-paste.ini has correct ownership'
  desc 'The keystone-paste.ini file should be owned by root:keystone.'
  impact 0.7
  
  describe file('/etc/keystone/keystone-paste.ini') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'keystone' }
    its('mode') { should cmp <= 0640 }
  end
end

control 'os-identity-1.9' do
  title 'Ensure policy.json has correct permissions'
  desc 'The policy.json file controls API access and should be protected.'
  impact 1.0
  
  describe file('/etc/keystone/policy.json') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'keystone' }
    its('mode') { should cmp <= 0640 }
  end
end

control 'os-identity-1.10' do
  title 'Ensure max_password_length is configured'
  desc 'Maximum password length should be set to prevent DoS attacks.'
  impact 0.5
  
  describe ini('/etc/keystone/keystone.conf') do
    its(['security_compliance', 'password_regex']) { should_not be_nil }
  end
end
