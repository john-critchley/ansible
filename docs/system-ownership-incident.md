# System ownership incident — 2026-07-09

## Follow-up, 2026-09-05

The original note identifies only a local environment with uid 1000 (admin),
not a hostname or instance ID. It says pomelo was unreachable. Do not assume
this was pomelo, kelp or gravlax, or declare the affected environment repaired.

Read-only checks on pomelo, kelp and gravlax found no ownership problems in the
critical root, sudo and SSH paths. SSH config parsing and passwordless sudo
work on all three. Their current UID maps are full identity maps and their root
filesystems are ext4. This does not establish the July environment's mapping.

The retained /var/log/ansible.log on pomelo has no July 9 entries. Reviewed
current provisioning, home migration, controller synchronisation, archive
extraction, active Samba and legacy roles. No demonstrated cause was found.

The separate, untracked ansible-roles checkout contains a legacy Samba task
that recursively assigns nobody:nogroup to public_share_path. Its default is
/samba/public, guarded by a preceding stat requiring the target to be absent.
The active top-level samba role does not contain that public-share task.
This is a potential operation to investigate in historical execution evidence,
not proof of a root-tree chown. The inspected sync targets are home directories;
archive destinations are application/JDK paths. Historical overrides, restores,
manual commands and the original mount/user namespace remain unknown.

## Prevention now implemented

`files/audit_system_ownership.py` is read-only and requires no sudo. It checks
critical Debian/Ubuntu access-path ownership (root:root), unsafe group/other
write permissions, the sudo setuid bit, SSH config snippets and symlink targets
and their parents. It emits UID/GID maps to help distinguish namespace mapping
from actual inode changes. This is a targeted access audit, not a complete
package integrity check or a continuous monitor.

```
python3 files/audit_system_ownership.py
ansible-playbook audit_system_ownership.yml
ansible-playbook audit_system_ownership.yml -e target=HOST
```

The standalone playbook defaults to kelp and gravlax. launch_instance.yml and
setup_server.yml execute the audit before privileged fact gathering, including
tagged/check-mode runs. Failures stop that host before provisioning proceeds.
It still needs working SSH transport and Python; a host already locked out
needs its existing root session, console or rescue environment.

Validation: pomelo local audit, remote audits and check mode on kelp/gravlax,
playbook syntax checks, plus disposable-file tests for nobody ownership,
unsafe modes and symlink inode handling (`sudo python3 -B tests/test_system_ownership.py`).

## Recovery still requires identifying the original environment

Before any repair, capture hostname/instance identity, numeric ownership,
/proc/self/uid_map and gid_map, mount information and relevant provisioning or
restore logs. If ownership is mapped through a container/user namespace or
filesystem, repair that mapping rather than rewriting package inode ownership.

If actual host inode damage is confirmed, keep a root console/session open.
The old note's explicit-path script is only an emergency access repair, not a
complete restoration. Verify owners/modes against the installed distribution's
package metadata and local overrides before applying it; do not recursively
chown /, /etc or /usr. Afterward validate sudoers with visudo, SSH configuration
with ssh -G localhost, and a separate sudo/SSH login before closing the rescue
session. Broad package ownership damage requires a wider package audit or
rebuild from trusted media, even if access is restored.

Open: identify July host/environment, determine whether it still exists, obtain
its historical mapping/execution evidence, then repair only if damage remains.
