"""Exercise inode checks on disposable files; run with sudo for UID fixtures."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('audit', Path(__file__).resolve().parents[1] / 'files/audit_system_ownership.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


@unittest.skipUnless(os.geteuid() == 0, 'root required for disposable ownership fixtures')
class OwnershipTests(unittest.TestCase):
    def test_drift_and_write_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config'
            path.write_text('fixture')
            path.chmod(0o644)
            self.assertEqual(audit.inspect(path), [])
            os.chown(path, 65534, 65534)
            self.assertTrue(any('65534:65534' in issue for issue in audit.inspect(path)))
            self.assertEqual(path.stat().st_uid, 65534)  # audit must not repair
            os.chown(path, 0, 0)
            path.chmod(0o666)
            self.assertTrue(any('writable' in issue for issue in audit.inspect(path)))

    def test_symlink_mode_is_not_reported_as_world_writable(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            target.touch()
            link = Path(directory) / 'link'
            link.symlink_to(target)
            self.assertEqual(audit.inspect(link), [])
            os.chown(link, 65534, 65534, follow_symlinks=False)
            self.assertTrue(audit.inspect(link))
            self.assertEqual(target.stat().st_uid, 0)


if __name__ == '__main__':
    unittest.main()
