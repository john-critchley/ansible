# Ansible repo

Documentation is in notes at key `ansible` (notes CLI: `notes read ansible`).

## Key points

- `secrets.yml` is NOT in this repo — copy separately via scp, pass with `-e @secrets.yml`
- Inventory: `hosts.ini`, region-grouped, fungi naming scheme
- Playbooks call scripts from `~/aws/` (awslaunch.py, aws_open_port.py, awsctl.py) on localhost
