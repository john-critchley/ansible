# -*- coding: utf-8 -*-
# WLST online script: register Google JWT Identity Asserter in the WebLogic realm.
#
# Run AFTER WebLogic has started with the JAR already in mbeantypes/ so the
# provider class is visible to the classloader.
#
# Run with:
#   wlst.sh config_jwt_asserter.py
#
# Environment variables:
#   WLS_ADMIN_PASS  — WebLogic admin password (required)
#   JWT_JWKS_URL    — JWKS URL (default: Google's endpoint)
#   JWT_AUDIENCE    — Expected aud claim / OAuth2 client ID (optional)
#
# Provider order after this script:
#   1. LDAPAuth              (SUFFICIENT) — authenticates LDAP users
#   2. DefaultAuthenticator              — fallback for local users (weblogic)
#   3. DefaultIdentityAsserter           — handles weblogic-jwt-token, X-Client-Cert
#   4. GoogleJwtAsserter                 — handles Authorization: Bearer <google-id-token>

import os
import jarray
from javax.management import ObjectName

wls_url  = 't3://localhost:7001'
wls_user = 'weblogic'
wls_pass = os.environ.get('WLS_ADMIN_PASS')
if not wls_pass:
    raise Exception('WLS_ADMIN_PASS environment variable not set')

domain        = 'base_domain'
realm         = 'myrealm'
provider_name = 'GoogleJwtAsserter'
provider_class = 'biz.critchley.weblogic.jwt.GoogleJwtAssertionProvider'

jwks_url = os.environ.get('JWT_JWKS_URL', 'https://www.googleapis.com/oauth2/v3/certs')
audience = os.environ.get('JWT_AUDIENCE', '')

realm_path    = '/SecurityConfiguration/' + domain + '/Realms/' + realm
provider_path = realm_path + '/AuthenticationProviders/' + provider_name

print('Connecting to WebLogic at ' + wls_url + ' ...')
connect(wls_user, wls_pass, wls_url)
edit()
startEdit()

print('Creating ' + provider_name + ' provider ...')
cd(realm_path)
cmo.createAuthenticationProvider(provider_name, provider_class)

cd(provider_path)
cmo.setActiveTypes(["Bearer"])
cmo.setJwksUrl(jwks_url)
cmo.setStripEmailDomain(True)
if audience:
    cmo.setExpectedAudience(audience)
    print('Audience set to: ' + audience)
else:
    print('No audience configured — aud claim will not be checked.')

# Reorder: keep existing authenticators; append JWT asserter at the end.
# Identity asserters are separate from password-based authenticators but live in
# the same AuthenticationProviders list.
print('Reordering authentication providers ...')
cd(realm_path)
set('AuthenticationProviders', jarray.array([
    ObjectName('Security:Name=' + realm + 'LDAPAuth'),
    ObjectName('Security:Name=' + realm + 'DefaultAuthenticator'),
    ObjectName('Security:Name=' + realm + 'DefaultIdentityAsserter'),
    ObjectName('Security:Name=' + realm + provider_name),
], ObjectName))

print('Saving and activating ...')
save()
activate(block='true')
disconnect()

print('Google JWT Identity Asserter registered successfully.')
print('Restart WebLogic to activate the new provider.')
exit()
