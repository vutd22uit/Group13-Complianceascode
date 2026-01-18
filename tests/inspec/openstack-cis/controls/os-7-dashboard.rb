# OpenStack Horizon (Dashboard) Security Controls
# CIS OpenStack Benchmark

control 'os-dashboard-7.1' do
  title 'Ensure Horizon uses HTTPS'
  desc 'Dashboard should only be accessible over HTTPS.'
  impact 1.0
  refs 'CIS OpenStack Benchmark', version: '1.0', section: '7.1'
  
  describe file('/etc/openstack-dashboard/local_settings.py') do
    its('content') { should match /SECURE_PROXY_SSL_HEADER.*=.*True/ }
  end
end

control 'os-dashboard-7.2' do
  title 'Ensure CSRF protection is enabled'
  desc 'Cross-Site Request Forgery protection must be enabled.'
  impact 1.0
  
  describe file('/etc/openstack-dashboard/local_settings.py') do
    its('content') { should match /CSRF_COOKIE_SECURE.*=.*True/ }
  end
end

control 'os-dashboard-7.3' do
  title 'Ensure session cookies are secure'
  desc 'Session cookies should be marked as secure and httponly.'
  impact 1.0
  
  describe file('/etc/openstack-dashboard/local_settings.py') do
    its('content') { should match /SESSION_COOKIE_SECURE.*=.*True/ }
    its('content') { should match /SESSION_COOKIE_HTTPONLY.*=.*True/ }
  end
end

control 'os-dashboard-7.4' do
  title 'Ensure password autocomplete is disabled'
  desc 'Password fields should have autocomplete disabled.'
  impact 0.5
  
  describe file('/etc/openstack-dashboard/local_settings.py') do
    its('content') { should match /HORIZON_CONFIG.*password_autocomplete.*off/ }
  end
end

control 'os-dashboard-7.5' do
  title 'Ensure session timeout is configured'
  desc 'User sessions should timeout after a period of inactivity.'
  impact 0.7
  
  describe file('/etc/openstack-dashboard/local_settings.py') do
    its('content') { should match /SESSION_TIMEOUT/ }
  end
end

control 'os-dashboard-7.6' do
  title 'Ensure DEBUG mode is disabled'
  desc 'DEBUG mode should never be enabled in production.'
  impact 1.0
  
  describe file('/etc/openstack-dashboard/local_settings.py') do
    its('content') { should match /DEBUG.*=.*False/ }
  end
end

control 'os-dashboard-7.7' do
  title 'Ensure local_settings.py has correct permissions'
  desc 'Dashboard configuration should be protected.'
  impact 0.8
  
  describe file('/etc/openstack-dashboard/local_settings.py') do
    it { should exist }
    its('mode') { should cmp <= 0640 }
  end
end
