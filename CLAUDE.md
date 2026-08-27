# Ansible repo

Documentation is in notes at key `ansible` (notes CLI: `notes read ansible`).

## Key points

- `secrets.yml` is NOT in this repo — copy separately via scp, pass with `-e @secrets.yml`
- Inventory: `hosts.ini`, region-grouped, fungi naming scheme
- Playbooks call scripts from `~/aws/` (awslaunch.py, aws_open_port.py, awsctl.py) on localhost
- `setup_browser_host.yml` configures a host as a headless Firefox+TigerVNC(:1)+XFCE browser host, driven via `ffdrive`/xdotool and reachable over stunnel. Size it with enough RAM to avoid swap (t3.large+). See notes `ansible/aws-browser-host`.
