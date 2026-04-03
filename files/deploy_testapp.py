# WLST online script: deploy testapp.war to AdminServer
#
# Run with:
#   wlst.sh deploy_testapp.py
#
# Environment variables:
#   WLS_ADMIN_PASS  -- WebLogic admin password (required)
#   TESTAPP_WAR     -- path to testapp.war (required)

import os

wls_url  = 't3://localhost:7001'
wls_user = 'weblogic'
wls_pass = os.environ.get('WLS_ADMIN_PASS')
if not wls_pass:
    raise Exception('WLS_ADMIN_PASS environment variable not set')

war_path = os.environ.get('TESTAPP_WAR')
if not war_path:
    raise Exception('TESTAPP_WAR environment variable not set')

print('Connecting to WebLogic at ' + wls_url + ' ...')
connect(wls_user, wls_pass, wls_url)

print('Deploying testapp from ' + war_path + ' ...')
deploy('testapp', war_path, targets='AdminServer', upload='true', block='true')

print('testapp deployed successfully.')
disconnect()
exit()
