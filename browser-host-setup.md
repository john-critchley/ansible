# Kombu Browser Host Setup & Automation Guide

**Date:** 2026-08-29  
**Instance:** kombu (i-0821c12d318240f4a), t4g.large ARM, eu-central-1  
**IP:** 63.186.248.220

## Completed Steps

### 1. EC2 Instance Provisioning ✅
```bash
AWS_PROFILE=provision ~/aws/awslaunch.py kombu t4g.large \
  --region eu-central-1 --ami ami-08241d277446b81d7
```
**Result:** Instance launched, SSH key generated at `~/.ssh/kombu.pem`, security group configured

### 2. Ansible Playbook (Browser Stack) ✅
```bash
cd ~/git/ansible
~/.local/bin/ansible-playbook setup_browser_host.yml -i hosts.ini \
  -e 'target=kombu' --limit kombu
```
**Installed:**
- Firefox-ESR
- TigerVNC (xtigervnc-standalone-server)
- XFCE4 desktop environment
- ImageMagick with libheic
- xdotool, fonts, utilities

**Issue Found:** Ansible installed packages but didn't auto-start VNC or X session. Requires manual startup.

### 3. Manual X Session & VNC Startup ✅
```bash
# On kombu:
export DISPLAY=:1
nohup startxfce4 > ~/.vnc/xfce4.log 2>&1 &
sleep 3

vncserver -geometry 1920x1080 -depth 24 -SecurityTypes None -localhost no :1
```

**Result:**
- Xtigervnc running (PID 17320)
- Listening on 127.0.0.1:5901 and [::1]:5901
- XFCE4 session active (PID 17328)
- Firefox started (PID 17497, multiple child processes)

### 4. /etc/hosts Update ✅
```bash
echo '63.186.248.220 kombu kombu.critchley.biz' | sudo tee -a /etc/hosts
```

### 5. SSH Tunnel Setup ✅
```bash
# From kelp:
ssh -i ~/.ssh/kombu.pem -o StrictHostKeyChecking=no -fN \
  -L 5902:localhost:5901 admin@kombu &
```
**Result:** VNC forwarding 127.0.0.1:5902 → kombu:5901

### 6. Delay Repay Toolkit Ready ✅
- Location: ~/delayrepay/ on kelp
- Includes: webdrive/, claim/, runner.py, keepalive.py
- Configuration: claim.conf (points to kombu)

## Issues Encountered & Solutions

### Issue 1: VNC Password Prompt
**Problem:** `vncserver` without flags prompted for password interactively  
**Solution:** Use `-SecurityTypes None -localhost no` flags; add `--I-KNOW-THIS-IS-INSECURE` for unauthenticated mode

### Issue 2: X Display Not Starting
**Problem:** VNC didn't launch without active X session  
**Solution:** Start XFCE4 first (`startxfce4`) before vncserver; use `export DISPLAY=:1`

### Issue 3: SSH Key Access from Local Machine
**Problem:** kombu.pem not accessible from non-kelp machines  
**Solution:** Use SSH through kelp (multi-hop) or pre-share key to local ~/.ssh/

### Issue 4: GWR Page Not Loading
**Problem:** Firefox opened but GWR website not displayed; OCR finding no text  
**Status:** Needs investigation - Firefox may need homepage set or explicit navigation timeout

## Recommended Playbook Additions

Create a new task in `setup_browser_host.yml` to auto-start X and VNC:

```yaml
- name: Configure and start VNC server
  block:
    - name: Create .vnc directory
      file:
        path: /home/admin/.vnc
        state: directory
        mode: '0700'

    - name: Start XFCE desktop on display :1
      shell: |
        export DISPLAY=:1
        nohup startxfce4 > ~/.vnc/xfce4.log 2>&1 &
      become_user: admin
      async: 30
      poll: 0

    - name: Wait for X to initialize
      pause:
        seconds: 4

    - name: Start TigerVNC server
      shell: |
        vncserver \
          -geometry 1920x1080 \
          -depth 24 \
          -SecurityTypes None \
          -localhost=no \
          :1
      become_user: admin
      register: vnc_start
      retries: 3
      delay: 2

    - name: Verify VNC is listening
      wait_for:
        port: 5901
        host: localhost
        timeout: 10
      tags: vnc_verify

    - name: Start Firefox
      shell: |
        export DISPLAY=:1
        nohup firefox > ~/.vnc/firefox.log 2>&1 &
      become_user: admin
      async: 30
      poll: 0
```

## For Future Automation

**File to create:** `~/later/01_setup_vnc.sh`
```bash
#!/bin/bash
# Setup script to be run after Ansible provisioning
# Usage: ssh admin@kombu < ~/later/01_setup_vnc.sh

set -ex

export DISPLAY=:1
export XAUTHORITY=~/.Xauthority

mkdir -p ~/.vnc
chmod 700 ~/.vnc

nohup startxfce4 > ~/.vnc/xfce4.log 2>&1 &
sleep 4

vncserver -geometry 1920x1080 -depth 24 -SecurityTypes None \
  -localhost=no --I-KNOW-THIS-IS-INSECURE :1 2>&1 | tee ~/.vnc/vncserver.log

sleep 2

# Verify VNC running
vncserver -list
echo "VNC ready on 5901"

# Start Firefox
nohup firefox > ~/.vnc/firefox.log 2>&1 &
echo "Firefox started"
```

## Infrastructure Map

```
pomelo/macbook
    └─ (VNC viewer, optional)
       └─ stunnel client → (mTLS)
kelp (controller)
    ├─ ~/.ssh/kombu.pem (SSH key)
    ├─ ~/git/ansible/ (playbooks)
    ├─ ~/delayrepay/ (toolkit)
    └─ SSH tunnel → localhost:5902 ↔ kombu:5901
        └─ kombu (browser host)
           ├─ Firefox on :1
           ├─ TigerVNC on 5901
           └─ XFCE4 desktop
```

## Next Steps

1. **Fix GWR page loading:** Check browser console, network, redirects; may need Homepage preference or explicit wait
2. **Generate stunnel certs:** Replace SSH tunnel with mTLS (ssl-patterns role)
3. **Test full claim flow:** Once GWR login visible, validate OCR + patch matching
4. **Integrate VNC startup into playbook:** Move manual steps to Ansible
5. **Create teardown scripts:** Document instance cleanup (~/later/ workflow)

## Reference Files

- Claim runner: `/home/john/delayrepay/claim/runner.py`
- Toolkit: `/home/john/delayrepay/webdrive/`
- VNC logs: `/home/admin/.vnc/xfce4.log`, `/home/admin/.vnc/firefox.log`
- Screenshot evidence: `https://webdav.critchley.biz/delayrepay/run/`
