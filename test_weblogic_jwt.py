#!/usr/bin/env python3
"""
End-to-end test: Google OAuth2 login → Perl app → WebLogic JWT asserter.
Also tests break-glass emergency access (/breakglass route).

Runs non-interactively. Saves screenshots at every significant step.
Screenshots written to ~/ansible/test-evidence/<timestamp>/
Exit code 0 = pass, 1 = fail.

Tests:
  1. JWT flow   — Google login → bearer token → WebLogic testapp → 200
  2. Break-glass correct creds  → BREAK-GLASS ACCESS GRANTED
  3. Break-glass wrong creds    → rejected (401)
"""

import os
import json
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

# ── Config ────────────────────────────────────────────────────────────────────

# Local runs execute from the dedicated WebLogic source file.
PERL_APP        = os.path.expanduser('~/ansible/files/weblogic_auth_app.pl')
CREDS_JSON      = os.path.expanduser(
    '~/Desktop/client_secret_1048362443290-'
    '2b5qj413ojqmhnapn36ih59j0m6bl2b3.apps.googleusercontent.com.json'
)
APP_URL         = 'http://localhost:8080/'
APP_PORT        = 8080
FIREFOX_PROFILE      = os.path.expanduser('~/.mozilla/firefox/0tckkbwo.default-esr-1')
FIREFOX_PROFILE_COPY = os.path.expanduser('~/ansible/tmp/ff_profile_copy')

BREAKGLASS_USER = 'breakglass'
BREAKGLASS_PASS = 'Br3akGl@ss1'
BREAKGLASS_WRONG_PASS = 'WrongPassword1!'

GOOGLE_LOGIN_TIMEOUT = 60
APP_TIMEOUT          = 30
POLL_INTERVAL        = 0.5   # WebDriverWait polls at this interval (seconds)

RUN_ID   = datetime.now().strftime('%Y%m%d_%H%M%S')
EVIDENCE = Path(os.path.expanduser(f'~/ansible/test-evidence/{RUN_ID}'))


# ── Evidence helpers ──────────────────────────────────────────────────────────

def log(msg):
    ts = datetime.now().strftime('%H:%M:%S')
    print(f'[{ts}] {msg}', flush=True)


def screenshot(driver, label):
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    seq = len(list(EVIDENCE.glob('*.png'))) + 1
    name = f'{seq:02d}_{label}.png'
    path = EVIDENCE / name
    driver.save_screenshot(str(path))
    log(f'  Screenshot: {path.name}  ({driver.current_url[:70]})')
    return path


def fail(driver, reason):
    log(f'  FAIL: {reason}')
    if driver:
        screenshot(driver, 'FAIL_' + reason[:40].replace(' ', '_'))
    return False


# ── Setup helpers ─────────────────────────────────────────────────────────────

def app_running():
    result = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True)
    return f':{APP_PORT}' in result.stdout


def start_perl_app():
    log(f'Starting Perl app on port {APP_PORT}...')
    env = os.environ.copy()
    env['OPS_TEST_ALLOW_ROLE_OVERRIDE'] = '1'
    proc = subprocess.Popen(
        ['perl', PERL_APP, 'daemon', '-l', f'http://*:{APP_PORT}',
         '--', '--creds', os.path.expanduser(CREDS_JSON)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    result = wait_until(lambda: app_running(), timeout=10, interval=0.5)
    if not result:
        log('  ERROR: Perl app did not start in time.')
        proc.terminate()
        sys.exit(1)
    log('  Perl app ready.')
    return proc


def profile_copy_ok(path):
    """Return True if a usable profile copy exists at path."""
    return (
        os.path.isdir(path)
        and os.path.isfile(os.path.join(path, 'prefs.js'))
    )


def make_profile_copy(force=False):
    dest = FIREFOX_PROFILE_COPY
    if not force and profile_copy_ok(dest):
        log(f'Reusing existing Firefox profile copy at {dest}')
        return dest
    if os.path.exists(dest):
        log(f'Removing stale profile copy at {dest} ...')
        shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    log(f'Copying Firefox profile to {dest} ...')
    shutil.copytree(FIREFOX_PROFILE, dest,
                    ignore=shutil.ignore_patterns('lock', 'parent.lock',
                                                  'places.sqlite-wal',
                                                  'places.sqlite-shm'))
    return dest


def make_driver(profile_dir):
    opts = Options()
    opts.profile = profile_dir
    opts.set_preference('dom.disable_beforeunload', True)
    opts.set_preference('browser.tabs.warnOnClose', False)
    opts.set_preference('signon.rememberSignons', False)
    driver = webdriver.Firefox(options=opts)
    driver.set_window_size(1200, 900)
    return driver


def wait_for(driver, condition, timeout, description):
    """Poll condition every POLL_INTERVAL seconds up to timeout.
    Takes a screenshot when condition is first met (terminal state).
    Returns the condition result, or None on timeout."""
    try:
        result = WebDriverWait(driver, timeout, poll_frequency=POLL_INTERVAL).until(condition)
        return result
    except Exception:
        log(f'  TIMEOUT waiting for: {description}')
        log(f'  Current URL: {driver.current_url}')
        screenshot(driver, 'timeout_' + description[:30].replace(' ', '_'))
        return None


def wait_until(fn, timeout=10, interval=0.5):
    """Poll a plain callable (no driver). Returns truthy result or None."""
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(interval)
    return None


def body_text(driver):
    try:
        return driver.find_element(By.TAG_NAME, 'body').text
    except Exception:
        return ''


def post_ops_action_http(driver, action, extra=None):
    cookie_header = '; '.join(f"{c['name']}={c['value']}" for c in driver.get_cookies())
    payload = {'action': action, 'format': 'json'}
    if extra:
        payload.update(extra)
    data = urllib.parse.urlencode(payload).encode('utf-8')
    req = urllib.request.Request(
        'http://localhost:8080/ops/action',
        data=data,
        method='POST',
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'Cookie': cookie_header,
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode('utf-8', errors='replace')


# ── Test 1: JWT flow ──────────────────────────────────────────────────────────

def step_navigate_to_app(driver):
    log('[1] Clearing any existing session via /logout')
    driver.get('http://localhost:8080/logout')
    # Poll until redirect lands back at localhost (or Google)
    wait_for(driver,
             lambda d: 'localhost:8080' in d.current_url or 'accounts.google.com' in d.current_url,
             APP_TIMEOUT, 'post-logout redirect')
    screenshot(driver, 'after_logout')

    log(f'[1] Navigating to {APP_URL}')
    driver.get(APP_URL)

    wait_for(driver,
             lambda d: 'localhost:8080' in d.current_url or 'accounts.google.com' in d.current_url,
             APP_TIMEOUT, 'post-app navigation redirect')

    if '/login' in driver.current_url:
        login_btn = wait_for(driver,
                             EC.element_to_be_clickable((By.ID, 'google-login-button')),
                             APP_TIMEOUT, 'google auth button on login choice page')
        if not login_btn:
            return fail(driver, 'google auth button missing on /login page')
        screenshot(driver, 'login_choice_page')
        login_btn.click()

    el = wait_for(driver, EC.url_contains('accounts.google.com'),
                  APP_TIMEOUT, 'redirect to Google')
    if not el and 'accounts.google.com' not in driver.current_url:
        if 'localhost:8080' in driver.current_url:
            log('  OAuth completed silently (Google still logged in). Fresh token acquired.')
            screenshot(driver, 'silent_oauth_complete')
            return True
        screenshot(driver, 'unexpected_url_after_navigate')
        return fail(driver, f'expected Google redirect, got {driver.current_url[:60]}')

    log('  Redirected to Google.')
    screenshot(driver, 'google_redirect')
    return True


def step_google_login(driver):
    log('[2] Google login')

    # "Choose an account" screen
    try:
        choose = WebDriverWait(driver, 5, poll_frequency=POLL_INTERVAL).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, '[data-email]'))
        )
        email = choose.get_attribute('data-email')
        log(f'  "Choose an account" — selecting {email}')
        screenshot(driver, 'choose_account')
        choose.click()
        return True
    except Exception:
        pass

    # Email input
    email_input = wait_for(driver,
                           EC.element_to_be_clickable(
                               (By.CSS_SELECTOR, 'input[type="email"]')),
                           10, 'email input')
    if not email_input:
        return fail(driver, 'email input not found')

    email_input.clear()
    email_input.send_keys('johnsrcritchley@gmail.com')
    screenshot(driver, 'email_entered')
    log('  Email entered.')

    next_btn = wait_for(driver,
                        EC.element_to_be_clickable((By.ID, 'identifierNext')),
                        5, 'Next button')
    if not next_btn:
        return fail(driver, 'Next button after email not found')
    next_btn.click()

    # Password input — poll until it appears and is filled
    password_input = wait_for(driver,
                              EC.element_to_be_clickable(
                                  (By.CSS_SELECTOR, 'input[type="password"]')),
                              10, 'password input')
    if not password_input:
        return fail(driver, 'password input not found')

    # Poll until auto-filled (Firefox password manager)
    filled = wait_for(driver,
                      lambda d: d.find_element(
                          By.CSS_SELECTOR, 'input[type="password"]').get_attribute('value'),
                      20, 'password auto-fill')
    if filled:
        log('  Password auto-filled.')
    else:
        log('  WARN: password not auto-filled after 20s.')

    screenshot(driver, 'password_ready')

    sign_in_btn = wait_for(driver,
                           EC.element_to_be_clickable((By.ID, 'passwordNext')),
                           5, 'Sign In button')
    if not sign_in_btn:
        return fail(driver, 'Sign In button not found')
    sign_in_btn.click()
    log('  Sign In clicked.')
    return True


def step_handle_oauth_consent(driver):
    try:
        allow = WebDriverWait(driver, 5, poll_frequency=POLL_INTERVAL).until(
            EC.element_to_be_clickable((By.XPATH,
                '//button[.//span[contains(text(),"Allow") or '
                'contains(text(),"Continue")]]'))
        )
        log('[2b] OAuth consent — clicking Allow.')
        screenshot(driver, 'oauth_consent')
        allow.click()
    except Exception:
        pass


def step_verify_app_response(driver):
    log('[3] Waiting for return to Perl app...')

    el = wait_for(driver, EC.url_contains('localhost'),
                  GOOGLE_LOGIN_TIMEOUT, 'return to localhost after login')
    if not el and 'localhost' not in driver.current_url:
        return fail(driver, f'still on {driver.current_url[:60]} after login')

    step_handle_oauth_consent(driver)

    # Poll until past /callback to the final route, then screenshot
    wait_for(driver,
             lambda d: 'localhost:8080' in d.current_url and '/callback' not in d.current_url,
             APP_TIMEOUT, 'final app page (past /callback)')

    screenshot(driver, 'app_home_response')
    body = body_text(driver)
    log(f'  Body: {body}')

    passed = True

    if 'WebLogic backend call succeeded' in body:
        log('  PASS: WebLogic backend call succeeded.')
    else:
        log('  FAIL: no success message from WebLogic.')
        passed = False

    if 'bearer' in body.lower() and 'basic-fallback' not in body.lower():
        log('  PASS: Bearer token auth confirmed.')
    elif 'basic-fallback' in body.lower():
        log('  FAIL: fell back to Basic auth — JWT asserter not working.')
        passed = False
    else:
        log('  INFO: auth mode not visible in body.')

    src = driver.page_source
    expected_links = ['/ops', '/debug', '/logout']
    missing = [href for href in expected_links if f'href="{href}"' not in src]
    if missing:
        log(f'  FAIL: home page missing navigation links: {missing}')
        passed = False
    else:
        log('  PASS: home page navigation links present.')

    # /debug endpoint — poll until body has content
    driver.get('http://localhost:8080/debug')
    wait_for(driver,
             lambda d: body_text(d).strip(),
             APP_TIMEOUT, 'debug page content')
    screenshot(driver, 'debug_endpoint')
    log(f'  /debug: {body_text(driver)}')

    return passed


def step_token_refresh(driver):
    log('[3b] Token refresh flow check via /debug/refresh')
    driver.get('http://localhost:8080/debug/refresh')

    wait_for(driver,
             lambda d: body_text(d).strip(),
             APP_TIMEOUT, 'debug refresh response')
    screenshot(driver, 'debug_refresh')

    body = body_text(driver)
    log(f'  /debug/refresh: {body}')

    if ('"ok" 1' in body or 'ok 1' in body) and ('"reason" "token refreshed"' in body or 'reason "token refreshed"' in body):
        log('  PASS: token refresh succeeded using refresh_token.')
        return True

    if '"has_refresh_token" 0' in body or 'has_refresh_token 0' in body or '"reason" "token expired and no refresh_token in session"' in body:
        return fail(driver, 'token refresh unavailable: no refresh_token in session')

    return fail(driver, 'token refresh endpoint did not report success')


def step_ops_controls(driver):
    log('[3c] Operations controls check via /ops')
    driver.get('http://localhost:8080/ops')

    wait_for(driver,
             lambda d: 'WebLogic Operations Control' in body_text(d),
             APP_TIMEOUT, 'ops page content')
    screenshot(driver, 'ops_page')

    page = body_text(driver)
    if 'WebLogic Operations Control' not in page:
        return fail(driver, 'ops page did not render correctly')

    rotate_btn = wait_for(driver,
                          EC.element_to_be_clickable((By.XPATH, '//button[contains(text(),"Rotate AdminServer Log")]')),
                          APP_TIMEOUT, 'rotate log button')
    if not rotate_btn:
        return fail(driver, 'rotate log button not available')
    rotate_btn.click()

    wait_for(driver,
             lambda d: 'Operation Result' in body_text(d),
             APP_TIMEOUT, 'rotate log result page')
    screenshot(driver, 'ops_rotate_response')
    rotate_body = body_text(driver)
    log(f'  /ops/action rotate response: {rotate_body}')
    if 'Result: EXECUTED' not in rotate_body or 'Log rotation triggered' not in rotate_body:
        return fail(driver, 'rotate_log action did not execute successfully')
    if 'Returning to Operations Control in 5 seconds.' not in rotate_body:
        return fail(driver, 'ops action page missing delayed redirect message')

    wait_for(driver,
             lambda d: 'localhost:8080/ops' in d.current_url,
             APP_TIMEOUT, 'return to /ops after rotate action')

    wait_for(driver,
             lambda d: 'Security Debug' in body_text(d),
             APP_TIMEOUT, 'ops page for debug toggle')
    screenshot(driver, 'ops_before_debug_toggle')

    before_ops = body_text(driver)
    if 'Security debug: OFF' in before_ops:
        first_action = 'security_debug_on'
        expected_after_first = 'ON'
        expected_after_restore = 'OFF'
    elif 'Security debug: ON' in before_ops:
        first_action = 'security_debug_off'
        expected_after_first = 'OFF'
        expected_after_restore = 'ON'
    else:
        return fail(driver, 'unable to determine initial security debug state from /ops page')

    try:
        first_resp = post_ops_action_http(driver, first_action)
    except Exception as exc:
        return fail(driver, f'first security debug toggle request failed: {exc}')
    screenshot(driver, 'ops_debug_toggle_1')
    log(f'  /ops/action debug response #1: {first_resp}')
    if 'executed' not in first_resp and 'already_in_requested_state' not in first_resp:
        return fail(driver, 'first security debug toggle failed')

    def wait_for_ops_state(expected_state, description):
        import time
        deadline = time.monotonic() + APP_TIMEOUT
        last_body = ''
        while time.monotonic() < deadline:
            driver.get('http://localhost:8080/ops')
            wait_for(driver,
                     lambda d: 'Security Debug' in body_text(d),
                     APP_TIMEOUT, f'ops page content ({description})')
            last_body = body_text(driver)
            if f'Security debug: {expected_state}' in last_body:
                return last_body
            time.sleep(1)
        return None

    after_first_page = wait_for_ops_state(expected_after_first, 'after first toggle')
    if not after_first_page:
        return fail(driver, f'ops page did not reflect first debug state ({expected_after_first})')

    restore_action = 'security_debug_off' if first_action == 'security_debug_on' else 'security_debug_on'
    try:
        second_resp = post_ops_action_http(driver, restore_action)
    except Exception as exc:
        return fail(driver, f'security debug restore request failed: {exc}')

    after_restore_page = wait_for_ops_state(expected_after_restore, 'after restore toggle')
    screenshot(driver, 'ops_after_debug_restore')
    log(f'  /ops/action debug response #2: {second_resp}')
    if 'executed' not in second_resp and 'already_in_requested_state' not in second_resp:
        return fail(driver, 'second security debug toggle failed')
    if not after_restore_page:
        return fail(driver, f'ops page did not reflect restored debug state ({expected_after_restore})')

    log('  PASS: /ops actions executed and security debug was restored.')
    return True


def step_ops_deny_override(driver):
    log('[3d] Operations deny-path check (non-permitted role + override)')
    try:
        deny_resp = post_ops_action_http(
            driver,
            'rotate_log',
            {'force_attempt': '1', 'test_role': 'breakglass_audit'}
        )
    except Exception as exc:
        return fail(driver, f'ops deny request failed: {exc}')

    log(f'  /ops/action deny response: {deny_resp}')
    try:
        deny_json = json.loads(deny_resp)
    except Exception:
        return fail(driver, 'ops deny response was not valid JSON')

    if deny_json.get('allowed') not in (0, False):
        return fail(driver, 'ops deny-path unexpectedly allowed action')
    if deny_json.get('reason_code') != 'role_not_permitted':
        return fail(driver, f"unexpected deny reason_code: {deny_json.get('reason_code')}")
    if 'override attempt made' not in str(deny_json.get('message', '')):
        return fail(driver, 'deny response missing override attempt marker')

    trace_id = str(deny_json.get('trace_id', '')).strip()
    if not trace_id:
        return fail(driver, 'deny response missing trace_id')

    driver.get('http://localhost:8080/ops?decision=denied')
    wait_for(driver,
             lambda d: trace_id in body_text(d),
             APP_TIMEOUT, 'denied audit trace on ops page')
    screenshot(driver, 'ops_deny_audit')
    page = body_text(driver)
    if trace_id not in page or 'DENIED' not in page:
        return fail(driver, 'deny audit evidence not visible on /ops page')

    log('  PASS: backend denied override attempt and audit evidence is visible.')
    return True


# ── Test 2 & 3: Break-glass ───────────────────────────────────────────────────

def step_breakglass_correct_creds(driver):
    log('[4] Break-glass: correct credentials')
    driver.get('http://localhost:8080/breakglass')

    wait_for(driver, EC.presence_of_element_located((By.NAME, 'username')),
             APP_TIMEOUT, 'breakglass form loaded')
    screenshot(driver, 'breakglass_form')

    driver.find_element(By.NAME, 'username').send_keys(BREAKGLASS_USER)
    driver.find_element(By.NAME, 'password').send_keys(BREAKGLASS_PASS)
    screenshot(driver, 'breakglass_form_filled')
    driver.find_element(By.CSS_SELECTOR, 'input[type=submit]').click()

    # Poll until redirected away from /breakglass (success) or error appears on page
    wait_for(driver,
             lambda d: '/breakglass' not in d.current_url or 'failed' in body_text(d).lower(),
             APP_TIMEOUT, 'breakglass redirect or error (correct creds)')
    screenshot(driver, 'breakglass_correct_response')

    body = body_text(driver)
    url  = driver.current_url
    log(f'  URL: {url}  Body: {body[:80]}')
    if 'localhost:8080' in url and '/breakglass' not in url and 'Break-glass session active' in body:
        log('  PASS: break-glass with correct credentials redirected to app.')
        return True
    if 'localhost:8080' in url and '/breakglass' not in url and 'WebLogic Auth App' in body:
        log('  PASS: break-glass with correct credentials — home page reached.')
        return True
    return fail(driver, f'break-glass correct creds — unexpected response at {url}: {body[:80]}')


def step_breakglass_wrong_creds(driver):
    log('[5] Break-glass: wrong credentials must be rejected')
    driver.get('http://localhost:8080/breakglass')

    wait_for(driver, EC.presence_of_element_located((By.NAME, 'username')),
             APP_TIMEOUT, 'breakglass form loaded (wrong creds test)')
    screenshot(driver, 'breakglass_form_wrong')

    driver.find_element(By.NAME, 'username').send_keys(BREAKGLASS_USER)
    driver.find_element(By.NAME, 'password').send_keys(BREAKGLASS_WRONG_PASS)
    driver.find_element(By.CSS_SELECTOR, 'input[type=submit]').click()

    # Poll until error page appears or unexpected redirect
    wait_for(driver,
             lambda d: 'failed' in body_text(d).lower() or '/breakglass' not in d.current_url,
             APP_TIMEOUT, 'breakglass error page (wrong creds)')
    screenshot(driver, 'breakglass_wrong_response')

    body = body_text(driver)
    url  = driver.current_url
    log(f'  URL: {url}  Body: {body[:80]}')
    if 'failed' in body.lower() and 'Break-glass session active' not in body:
        log('  PASS: break-glass with wrong credentials correctly rejected.')
        return True
    return fail(driver, f'break-glass wrong creds — not rejected at {url}: {body[:80]}')


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--copy-profile', action='store_true',
                        help='Force a fresh copy of the Firefox profile before running')
    args = parser.parse_args()

    perl_proc = None
    driver    = None
    results   = {}

    log(f'Evidence directory: {EVIDENCE}')

    try:
        if app_running():
            log('Perl app already running — restarting with test env vars.')
            subprocess.run(['pkill', '-f', 'weblogic_auth_app.pl'], capture_output=True)
            wait_until(lambda: not app_running(), timeout=10, interval=0.5)
        perl_proc = start_perl_app()

        profile_dir = make_profile_copy(force=args.copy_profile)
        driver = make_driver(profile_dir)

        # Test 1: JWT flow
        ok = step_navigate_to_app(driver)
        if ok and 'accounts.google.com' in driver.current_url:
            ok = step_google_login(driver)
        results['jwt'] = ok and step_verify_app_response(driver)
        results['token_refresh'] = results['jwt'] and step_token_refresh(driver)
        results['ops_controls'] = results['token_refresh'] and step_ops_controls(driver)
        results['ops_deny_override'] = results['ops_controls'] and step_ops_deny_override(driver)

        # Tests 2 & 3: break-glass
        results['breakglass_correct'] = step_breakglass_correct_creds(driver)
        results['breakglass_wrong']   = step_breakglass_wrong_creds(driver)

    except Exception as e:
        log(f'EXCEPTION: {e}')
        if driver:
            screenshot(driver, 'EXCEPTION')
        raise

    finally:
        if driver:
            driver.quit()
        if perl_proc:
            log('Stopping Perl app.')
            perl_proc.terminate()

    log('')
    log('=== RESULTS ===')
    all_passed = True
    for name, passed in results.items():
        status = 'PASS' if passed else 'FAIL'
        log(f'  {status}  {name}')
        if not passed:
            all_passed = False

    log('')
    if all_passed:
        log('=== TEST PASSED ===')
        sys.exit(0)
    else:
        log('=== TEST FAILED === (see screenshots in test-evidence/)')
        sys.exit(1)


if __name__ == '__main__':
    main()
