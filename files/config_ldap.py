# WLST online script: configure OpenLDAP authentication in WebLogic
# Run after WebLogic is started.
# Run with: wlst.sh config_ldap.py
#
# Adds LDAPAuth provider to myrealm pointing at localhost OpenLDAP (critchley.biz),
# configures all user/group settings, and reorders providers so LDAP is tried first.
#
# Provider order after this script:
#   1. LDAPAuth (SUFFICIENT) - handles LDAP users (e.g. testuser)
#   2. DefaultAuthenticator  - fallback for local users (e.g. weblogic)
#   3. DefaultIdentityAsserter

import os
import jarray
from javax.management import ObjectName

wls_url  = 't3://localhost:7001'
wls_user = 'weblogic'
wls_pass = os.environ.get('WLS_ADMIN_PASS')
if not wls_pass:
    raise Exception('WLS_ADMIN_PASS environment variable not set')
domain   = 'base_domain'
realm    = 'myrealm'

realm_path    = '/SecurityConfiguration/' + domain + '/Realms/' + realm
provider_path = realm_path + '/AuthenticationProviders/LDAPAuth'

print('Connecting to WebLogic at ' + wls_url + ' ...')
connect(wls_user, wls_pass, wls_url)
edit()
startEdit()

# Create the LDAP Authenticator provider
print('Creating LDAPAuth provider ...')
cd(realm_path)
cmo.createAuthenticationProvider(
    'LDAPAuth',
    'weblogic.security.providers.authentication.LDAPAuthenticator'
)

# Configure the provider
cd(provider_path)
cmo.setControlFlag('SUFFICIENT')

# LDAP connection
cmo.setHost('localhost')
cmo.setPort(389)
cmo.setPrincipal('cn=admin,dc=critchley,dc=biz')
cmo.setCredential('ldappass')
cmo.setSSLEnabled(False)
cmo.setFollowReferrals(False)

# User configuration
cmo.setUserBaseDN('ou=users,ou=winterbourne,dc=critchley,dc=biz')
cmo.setUserNameAttribute('uid')
cmo.setUserObjectClass('inetOrgPerson')
cmo.setUserFromNameFilter('(&(uid=%u)(objectclass=inetOrgPerson))')
cmo.setUseRetrievedUserNameAsPrincipal(True)

# Group configuration - (member=%M) is CRITICAL for groupOfNames objectClass.
# Without this, users authenticate but have no groups, causing HTTP 403 on all
# REST API calls.
cmo.setGroupBaseDN('ou=groups,ou=winterbourne,dc=critchley,dc=biz')
cmo.setStaticGroupObjectClass('groupOfNames')
cmo.setStaticMemberDNAttribute('member')
cmo.setStaticGroupDNsfromMemberDNFilter('(member=%M)')
cmo.setGroupFromNameFilter('(cn=%g)')

# Reorder providers: LDAPAuth must come before DefaultAuthenticator
# ObjectName format: Security:Name=<realmname><providername>
print('Reordering authentication providers ...')
cd(realm_path)
set('AuthenticationProviders', jarray.array([
    ObjectName('Security:Name=' + realm + 'LDAPAuth'),
    ObjectName('Security:Name=' + realm + 'DefaultAuthenticator'),
    ObjectName('Security:Name=' + realm + 'DefaultIdentityAsserter'),
], ObjectName))

print('Saving and activating ...')
save()
activate(block='true')
disconnect()

print('LDAP authenticator configured successfully.')
print('Restart WebLogic for changes to take effect.')
exit()
