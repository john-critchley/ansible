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
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

# ── Config ────────────────────────────────────────────────────────────────────

PERL_APP        = os.path.expanduser('~/ansible/weekday/john/weblogic_auth_app.pl')
CREDS_JSON      = os.path.expanduser(
    '~/Desktop/client_secret_1048362443290-'
    '2b5qj413ojqmhnapn36ih59j0m6bl2b3.apps.googleusercontent.com.json'
)
APP_URL         = 'http://localhost:8080/'
APP_PORT        = 8080
FIREFOX_PROFILE = os.path.expanduser('~/.mozilla/firefox/0tckkbwo.default-esr-1')

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
    proc = subprocess.Popen(
        ['perl', PERL_APP, 'daemon', '-l', f'http://*:{APP_PORT}',
         '--', '--creds', os.path.expanduser(CREDS_JSON)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    result = wait_until(lambda: app_running(), timeout=10, interval=0.5)
    if not result:
        log('  ERROR: Perl app did not start in time.')
        proc.terminate()
        sys.exit(1)
    log('  Perl app ready.')
    return proc


def make_profile_copy():
    tmp = tempfile.mkdtemp(prefix='ff_profile_')
    log(f'Copying Firefox profile to {tmp} ...')
    shutil.copytree(FIREFOX_PROFILE, tmp, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns('lock', 'parent.lock',
                                                  'places.sqlite-wal',
                                                  'places.sqlite-shm'))
    return tmp


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

    # /debug endpoint — poll until body has content
    driver.get('http://localhost:8080/debug')
    wait_for(driver,
             lambda d: body_text(d).strip(),
             APP_TIMEOUT, 'debug page content')
    screenshot(driver, 'debug_endpoint')
    log(f'  /debug: {body_text(driver)}')

    return passed


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

    # Poll until body contains a terminal state (granted or failed)
    wait_for(driver,
             lambda d: 'GRANTED' in body_text(d) or 'failed' in body_text(d).lower(),
             APP_TIMEOUT, 'breakglass response (correct creds)')
    screenshot(driver, 'breakglass_correct_response')

    body = body_text(driver)
    log(f'  Body: {body}')
    if 'BREAK-GLASS ACCESS GRANTED' in body:
        log('  PASS: break-glass with correct credentials granted.')
        return True
    return fail(driver, f'break-glass correct creds — unexpected response: {body[:80]}')


def step_breakglass_wrong_creds(driver):
    log('[5] Break-glass: wrong credentials must be rejected')
    driver.get('http://localhost:8080/breakglass')

    wait_for(driver, EC.presence_of_element_located((By.NAME, 'username')),
             APP_TIMEOUT, 'breakglass form loaded (wrong creds test)')
    screenshot(driver, 'breakglass_form_wrong')

    driver.find_element(By.NAME, 'username').send_keys(BREAKGLASS_USER)
    driver.find_element(By.NAME, 'password').send_keys(BREAKGLASS_WRONG_PASS)
    driver.find_element(By.CSS_SELECTOR, 'input[type=submit]').click()

    # Poll until body contains a terminal state
    wait_for(driver,
             lambda d: 'GRANTED' in body_text(d) or 'failed' in body_text(d).lower(),
             APP_TIMEOUT, 'breakglass response (wrong creds)')
    screenshot(driver, 'breakglass_wrong_response')

    body = body_text(driver)
    log(f'  Body: {body}')
    if 'failed' in body.lower() and 'GRANTED' not in body:
        log('  PASS: break-glass with wrong credentials correctly rejected.')
        return True
    return fail(driver, f'break-glass wrong creds — not rejected: {body[:80]}')


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    perl_proc   = None
    profile_tmp = None
    driver      = None
    results     = {}

    log(f'Evidence directory: {EVIDENCE}')

    try:
        if app_running():
            log('Perl app already running.')
        else:
            perl_proc = start_perl_app()

        profile_tmp = make_profile_copy()
        driver = make_driver(profile_tmp)

        # Test 1: JWT flow
        ok = step_navigate_to_app(driver)
        if ok and 'accounts.google.com' in driver.current_url:
            ok = step_google_login(driver)
        results['jwt'] = ok and step_verify_app_response(driver)

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
        if profile_tmp and os.path.exists(profile_tmp):
            shutil.rmtree(profile_tmp, ignore_errors=True)
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
