import tempfile
import unittest

from database import Database


class SecurityLogicTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix='.db')
        self.db = Database(db_path=self.tmp.name)

    def tearDown(self):
        self.db.close()
        self.tmp.close()

    def test_auth_success_and_failure(self):
        ok, _ = self.db.authenticate_user('admin', 'admin123!Secure', source_ip='198.51.100.10')
        self.assertTrue(ok)
        bad, _ = self.db.authenticate_user('admin', 'wrong-password', source_ip='198.51.100.10')
        self.assertFalse(bad)

    def test_password_policy_validation_and_history(self):
        user = self.db.get_users(search='jsmith')[0]
        with self.assertRaises(ValueError):
            self.db.set_user_password(user['id'], 'short1!')

        self.db.set_user_password(user['id'], 'NewSecurePass#123')
        with self.assertRaises(ValueError):
            self.db.set_user_password(user['id'], 'NewSecurePass#123')

    def test_ai_analytics_and_risk_scoring(self):
        for _ in range(5):
            self.db.log_audit('admin', 'FAILED_LOGIN', 'user', 1, 'admin', 'failed login simulation', 'warning')

        ai = self.db.analyze_audit_log_ai()
        anomalies = self.db.detect_access_anomalies(failed_login_threshold=3)
        risk = self.db.explainable_risk_score(user_id=1, role_id=1)

        self.assertGreaterEqual(ai['total_events'], 1)
        self.assertTrue(any('mitre_attack' in f['mapping'] for f in ai['findings']))
        self.assertGreaterEqual(len(anomalies), 1)
        self.assertIn('score', risk)
        self.assertIn('factors', risk)

    def test_dynamic_columns_are_allowlisted(self):
        with self.assertRaises(ValueError):
            self.db.update_user(1, **{'status = ? WHERE 1=1 --': 'active'})
        with self.assertRaises(ValueError):
            self.db.create_role(**{'name': 'viewer', 'DROP TABLE users': 'x'})
        self.assertIsNotNone(self.db.get_user(1))


if __name__ == '__main__':
    unittest.main()
