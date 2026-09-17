#!/usr/bin/python3
"""Read-only Debian/Ubuntu access-path audit. Never repairs ownership."""
import json
import os
from pathlib import Path
import stat
import sys

REQUIRED = ('/', '/etc', '/usr', '/usr/bin', '/usr/lib', '/etc/ssh',
            '/etc/ssh/ssh_config', '/usr/bin/ssh', '/etc/sudoers', '/usr/bin/sudo')
OPTIONAL = ('/etc/sudo.conf', '/etc/sudoers.d', '/etc/ssh/ssh_config.d',
            '/usr/lib/systemd', '/usr/lib/systemd/ssh_config.d')


def inspect(path):
    info = path.lstat()
    issues = []
    if info.st_uid != 0 or info.st_gid != 0:
        issues.append(f'owner={info.st_uid}:{info.st_gid}, expected 0:0')
    if not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022:
        issues.append(f'group/other writable mode={stat.S_IMODE(info.st_mode):04o}')
    if str(path) == '/usr/bin/sudo' and not info.st_mode & stat.S_ISUID:
        issues.append('sudo setuid bit missing')
    return issues


def audit():
    problems = []
    paths = set(map(Path, REQUIRED))
    paths.update(Path(p) for p in OPTIONAL if os.path.lexists(p))
    for directory in ('/etc/ssh/ssh_config.d', '/usr/lib/systemd/ssh_config.d'):
        paths.update(Path(directory).glob('*.conf'))
    # Also inspect symlink destinations and each parent, not just the link inode.
    for path in list(paths):
        if path.is_symlink():
            try:
                resolved = path.resolve(strict=True)
                paths.add(resolved)
                paths.update(resolved.parents)
            except (OSError, RuntimeError) as exc:
                problems.append(f'{path}: cannot resolve link ({type(exc).__name__})')
    for path in sorted(paths):
        try:
            problems.extend(f'{path}: {issue}' for issue in inspect(path))
        except PermissionError:
            # sudoers may legitimately be unreadable, but its inode must be stat-able.
            problems.append(f'{path}: cannot inspect inode')
        except OSError as exc:
            problems.append(f'{path}: {type(exc).__name__}')
    return problems


if __name__ == '__main__':
    problems = audit()
    print(json.dumps({'host': os.uname().nodename, 'issues': problems,
                      'uid_map': Path('/proc/self/uid_map').read_text().strip(),
                      'gid_map': Path('/proc/self/gid_map').read_text().strip()}))
    sys.exit(bool(problems))
