# WLST offline script: create WebLogic base_domain from template
# Run with: wlst.sh create_domain.py
#
# Creates a Development mode domain with:
#   - AdminServer on HTTP 7001, SSL 7002 (demo cert, dev mode)
#   - Admin user: weblogic (password passed via WLS_ADMIN_PASS env var)
#   - Domain path: /home/john/Oracle/Middleware/Oracle_Home/user_projects/domains/base_domain
#
# Note: admin user is 'weblogic' (WLS template default), not 'john'.
# The 'john' name comes from LDAP after config_ldap.py runs.

import os

oracle_home = '/home/john/Oracle/Middleware/Oracle_Home'
domain_home = oracle_home + '/user_projects/domains/base_domain'
template    = oracle_home + '/wlserver/common/templates/wls/wls.jar'

admin_pass = os.environ.get('WLS_ADMIN_PASS')
if not admin_pass:
    raise Exception('WLS_ADMIN_PASS environment variable not set')

print('Reading WLS domain template: ' + template)
readTemplate(template)

# AdminServer listen address and HTTP port
cd('Servers/AdminServer')
set('ListenAddress', '')
set('ListenPort', 7001)

# Admin credentials (default template user is 'weblogic')
cd('/')
cd('Security/base_domain/User/weblogic')
cmo.setPassword(admin_pass)

# Write domain (Development mode, SSL enabled automatically on port 7002)
setOption('OverwriteDomain', 'true')
setOption('ServerStartMode', 'dev')

print('Writing domain to: ' + domain_home)
writeDomain(domain_home)
closeDomain()

print('Domain created successfully.')
exit()
