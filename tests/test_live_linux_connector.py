import unittest

from live_linux_connector import LinuxSSHConnector


class LiveLinuxConnectorTests(unittest.TestCase):
    def test_dry_run_create_user_is_safe_and_quoted(self):
        connector = LinuxSSHConnector(config={"dry_run": True, "sudo": True})
        result = connector.create_user("jdoe", "Jane Doe", "jdoe@example.com")

        self.assertTrue(result.success)
        self.assertTrue(result.dry_run)
        self.assertIn("DRY RUN", result.details)
        self.assertIn("useradd", result.details)
        self.assertIn("passwd -l", result.details)

    def test_rejects_unsafe_username(self):
        connector = LinuxSSHConnector(config={"dry_run": True})
        with self.assertRaises(ValueError):
            connector.create_user("bad;rm-rf", "Bad User")

    def test_assign_group_dry_run(self):
        connector = LinuxSSHConnector(config={"dry_run": True, "sudo": True})
        result = connector.assign_group("jdoe", "security")

        self.assertTrue(result.success)
        self.assertIn("groupadd", result.details)
        self.assertIn("usermod -aG", result.details)

    def test_test_connection_dry_run(self):
        connector = LinuxSSHConnector(config={"dry_run": True})
        result = connector.test_connection()

        self.assertTrue(result.success)
        self.assertIn("id", result.details)
        self.assertIn("uname -a", result.details)


if __name__ == "__main__":
    unittest.main()
