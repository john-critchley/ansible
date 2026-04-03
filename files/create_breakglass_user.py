# -*- coding: utf-8 -*-
# WLST online script: create break-glass emergency user in DefaultAuthenticator.
#
# Creates a local WebLogic user (not LDAP-sourced) in the Administrators group.
# This user can authenticate directly via Basic auth even if:
#   - Google OAuth2 is unavailable
#   - LDAP is down
#   - The JWT asserter is broken
#
# The DefaultAuthenticator is the last-resort fallback in the auth chain
# (LDAPAuth is SUFFICIENT, so if LDAP fails, DefaultAuthenticator is tried next).
#
# Run with:
#   wlst.sh create_breakglass_user.py
#
# Environment variables:
#   WLS_ADMIN_PASS    -- WebLogic admin password (required)
#   BREAKGLASS_PASS   -- password for the break-glass account (required)
#   BREAKGLASS_USER   -- username (default: breakglass)

import os

wls_url  = 't3://localhost:7001'
wls_user = 'weblogic'
wls_pass = os.environ.get('WLS_ADMIN_PASS')
if not wls_pass:
    raise Exception('WLS_ADMIN_PASS environment variable not set')

bg_pass = os.environ.get('BREAKGLASS_PASS')
if not bg_pass:
    raise Exception('BREAKGLASS_PASS environment variable not set')

bg_user = os.environ.get('BREAKGLASS_USER', 'breakglass')
domain  = 'base_domain'
realm   = 'myrealm'

print('Connecting to WebLogic at ' + wls_url + ' ...')
connect(wls_user, wls_pass, wls_url)

cd('/SecurityConfiguration/' + domain + '/Realms/' + realm + '/AuthenticationProviders/DefaultAuthenticator')

if cmo.userExists(bg_user):
    print('Break-glass user "' + bg_user + '" already exists — skipping creation.')
else:
    print('Creating break-glass user: ' + bg_user)
    cmo.createUser(bg_user, bg_pass, 'Emergency break-glass account - authorised use only')
    print('Adding to Administrators group ...')
    cmo.addMemberToGroup('Administrators', bg_user)
    print('Break-glass user created successfully.')

disconnect()
exit()
