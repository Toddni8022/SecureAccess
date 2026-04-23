import os
import tempfile
import unittest

from database import Database
from security_core import SecurityService


class SecurityServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.close()
        self.db = Database(self.tmp.name)
        self.security = SecurityService(self.db)

    def tearDown(self):
        self.db.close()
        os.unlink(self.tmp.name)

    def test_bootstrap_admin_auth_and_permissions(self):
        self.security.bootstrap_admin_password("SecureAccess!Test123")
        result = self.security.authenticate("admin", "SecureAccess!Test123")

        self.assertTrue(result.success)
        self.assertIsNotNone(result.user)
        self.assertTrue(self.security.has_permission(result.user["id"], "manage_roles"))
        self.assertTrue(result.permissions.get("all"))

    def test_password_policy_rejects_weak_password(self):
        result = self.security.validate_password_policy("weak")
        self.assertFalse(result.ok)
        self.assertGreaterEqual(len(result.problems), 1)

    def test_failed_login_eventually_locks_account(self):
        self.security.bootstrap_admin_password("SecureAccess!Test123")

        for _ in range(5):
            self.security.authenticate("admin", "wrong-password")

        admin = self.security.get_user_by_username("admin")
        self.assertIsNotNone(admin["locked_until"])

    def test_audit_chain_backfill_and_verify(self):
        self.security.backfill_audit_hashes()
        self.security.record_audit(
            actor="tester",
            action="UNIT_TEST_EVENT",
            target_type="test",
            target_name="audit",
            details="testing integrity chain",
        )
        result = self.security.verify_audit_chain()

        self.assertTrue(result.ok, result.problems)
        self.assertGreater(result.checked_records, 0)

    def test_backup_export_creates_hash_manifest(self):
        self.security.backfill_audit_hashes()
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "secureaccess-backup.json")
            manifest = self.security.export_backup(output)

            self.assertTrue(os.path.exists(output))
            self.assertEqual(len(manifest["sha256"]), 64)
            self.assertGreater(manifest["record_count"], 0)


if __name__ == "__main__":
    unittest.main()
