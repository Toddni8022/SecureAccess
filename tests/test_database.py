"""
Unit tests for SecureAccess database layer.
Uses an in-memory SQLite database so no files are created on disk.
"""

import json
import pytest
from database import Database, hash_password, verify_password, _validate_cols


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    """Provide a fresh in-memory database for every test."""
    d = Database(db_path=":memory:")
    yield d
    d.close()


# ── Password helpers ──────────────────────────────────────────────────────────

class TestPasswordHelpers:
    def test_hash_password_returns_string(self):
        h = hash_password("secret123")
        assert isinstance(h, str)

    def test_hash_password_starts_with_bcrypt_prefix(self):
        h = hash_password("secret123")
        assert h.startswith("$2b$")

    def test_hash_password_different_salts(self):
        h1 = hash_password("secret123")
        h2 = hash_password("secret123")
        assert h1 != h2  # bcrypt generates unique salts

    def test_verify_password_correct(self):
        h = hash_password("correct_horse_battery_staple")
        assert verify_password("correct_horse_battery_staple", h) is True

    def test_verify_password_wrong(self):
        h = hash_password("correct_horse_battery_staple")
        assert verify_password("wrong_password", h) is False

    def test_verify_password_invalid_hash(self):
        assert verify_password("password", "not-a-valid-hash") is False


# ── Column validation ─────────────────────────────────────────────────────────

class TestValidateCols:
    def test_valid_cols_pass(self):
        _validate_cols({'username', 'email'}, {'username', 'email', 'status'}, 'user')

    def test_unknown_col_raises(self):
        with pytest.raises(ValueError, match="Invalid user column"):
            _validate_cols({'username', '; DROP TABLE users'}, {'username'}, 'user')

    def test_empty_cols_pass(self):
        _validate_cols(set(), {'username'}, 'user')


# ── Database initialisation ───────────────────────────────────────────────────

class TestDatabaseInit:
    def test_tables_created(self, db):
        tables = {row[0] for row in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        assert {'users', 'roles', 'user_roles', 'access_requests',
                'audit_log', 'password_policy', 'access_reviews', 'review_items'} <= tables

    def test_default_roles_seeded(self, db):
        roles = db.get_roles()
        assert len(roles) == 7
        names = [r['name'] for r in roles]
        assert 'Administrator' in names
        assert 'Standard User' in names

    def test_default_users_seeded(self, db):
        users = db.get_users()
        assert len(users) == 10

    def test_password_policy_seeded(self, db):
        policy = db.get_password_policy()
        assert policy is not None
        assert policy['min_length'] == 12

    def test_audit_log_seeded(self, db):
        entries = db.get_audit_log(limit=50)
        assert len(entries) > 0


# ── User CRUD ─────────────────────────────────────────────────────────────────

class TestUserCRUD:
    def test_create_user(self, db):
        db.create_user(username='testuser', display_name='Test User', email='test@example.com')
        user = db.conn.execute("SELECT * FROM users WHERE username='testuser'").fetchone()
        assert user is not None
        assert user['display_name'] == 'Test User'

    def test_create_user_hashes_password(self, db):
        db.create_user(username='pwuser', display_name='PW User', password='PlainText123!')
        user = db.conn.execute("SELECT * FROM users WHERE username='pwuser'").fetchone()
        assert user['password_hash'] is not None
        assert user['password_hash'] != 'PlainText123!'
        assert verify_password('PlainText123!', user['password_hash'])

    def test_create_user_invalid_column_raises(self, db):
        with pytest.raises(ValueError):
            db.create_user(username='bad', display_name='Bad', malicious_col='DROP TABLE')

    def test_get_user(self, db):
        db.create_user(username='getme', display_name='Get Me')
        row = db.conn.execute("SELECT id FROM users WHERE username='getme'").fetchone()
        user = db.get_user(row['id'])
        assert user['username'] == 'getme'

    def test_get_user_not_found_returns_none(self, db):
        assert db.get_user(99999) is None

    def test_update_user(self, db):
        db.create_user(username='upd', display_name='Update Me')
        row = db.conn.execute("SELECT id FROM users WHERE username='upd'").fetchone()
        db.update_user(row['id'], status='inactive')
        updated = db.get_user(row['id'])
        assert updated['status'] == 'inactive'

    def test_update_user_hashes_password(self, db):
        db.create_user(username='upd2', display_name='Update PW')
        row = db.conn.execute("SELECT id FROM users WHERE username='upd2'").fetchone()
        db.update_user(row['id'], password='NewPassword99!')
        user = db.get_user(row['id'])
        assert verify_password('NewPassword99!', user['password_hash'])

    def test_delete_user(self, db):
        db.create_user(username='delme', display_name='Delete Me')
        row = db.conn.execute("SELECT id FROM users WHERE username='delme'").fetchone()
        db.delete_user(row['id'])
        assert db.get_user(row['id']) is None

    def test_get_users_status_filter(self, db):
        active = db.get_users(status_filter='active')
        inactive = db.get_users(status_filter='inactive')
        assert all(u['status'] == 'active' for u in active)
        assert all(u['status'] == 'inactive' for u in inactive)

    def test_get_users_search(self, db):
        results = db.get_users(search='admin')
        usernames = [u['username'] for u in results]
        assert 'admin' in usernames


# ── Role CRUD ─────────────────────────────────────────────────────────────────

class TestRoleCRUD:
    def test_create_role(self, db):
        db.create_role(name='TestRole', description='A test role', risk_level='low')
        role = db.conn.execute("SELECT * FROM roles WHERE name='TestRole'").fetchone()
        assert role is not None
        assert role['risk_level'] == 'low'

    def test_create_role_invalid_column_raises(self, db):
        with pytest.raises(ValueError):
            db.create_role(name='Bad', bad_col='value')

    def test_update_role(self, db):
        db.create_role(name='UpdRole', description='Before', risk_level='low')
        row = db.conn.execute("SELECT id FROM roles WHERE name='UpdRole'").fetchone()
        db.update_role(row['id'], description='After')
        role = db.get_role(row['id'])
        assert role['description'] == 'After'

    def test_delete_role(self, db):
        db.create_role(name='DelRole', description='Gone', risk_level='low')
        row = db.conn.execute("SELECT id FROM roles WHERE name='DelRole'").fetchone()
        db.delete_role(row['id'])
        assert db.get_role(row['id']) is None


# ── Role assignments ──────────────────────────────────────────────────────────

class TestRoleAssignments:
    def test_assign_and_get_user_roles(self, db):
        db.create_user(username='ra_user', display_name='RA User')
        db.create_role(name='RA Role', description='Test', risk_level='low')
        uid = db.conn.execute("SELECT id FROM users WHERE username='ra_user'").fetchone()['id']
        rid = db.conn.execute("SELECT id FROM roles WHERE name='RA Role'").fetchone()['id']
        db.assign_role(uid, rid, granted_by='tester', justification='Testing')
        roles = db.get_user_roles(uid)
        assert any(r['name'] == 'RA Role' for r in roles)

    def test_revoke_role(self, db):
        db.create_user(username='rv_user', display_name='RV User')
        db.create_role(name='RV Role', description='Test', risk_level='low')
        uid = db.conn.execute("SELECT id FROM users WHERE username='rv_user'").fetchone()['id']
        rid = db.conn.execute("SELECT id FROM roles WHERE name='RV Role'").fetchone()['id']
        db.assign_role(uid, rid)
        db.revoke_role(uid, rid)
        roles = db.get_user_roles(uid)
        assert not any(r['name'] == 'RV Role' for r in roles)

    def test_get_role_users(self, db):
        db.create_user(username='ru_user', display_name='RU User')
        db.create_role(name='RU Role', description='Test', risk_level='low')
        uid = db.conn.execute("SELECT id FROM users WHERE username='ru_user'").fetchone()['id']
        rid = db.conn.execute("SELECT id FROM roles WHERE name='RU Role'").fetchone()['id']
        db.assign_role(uid, rid)
        users = db.get_role_users(rid)
        assert any(u['username'] == 'ru_user' for u in users)


# ── Access requests ───────────────────────────────────────────────────────────

class TestAccessRequests:
    def _ids(self, db):
        uid = db.conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()['id']
        rid = db.conn.execute("SELECT id FROM roles WHERE name='Auditor'").fetchone()['id']
        return uid, rid

    def test_create_access_request(self, db):
        uid, rid = self._ids(db)
        db.create_access_request(uid, rid, justification='Need audit access')
        requests = db.get_access_requests(status_filter='pending')
        assert len(requests) > 0

    def test_review_access_request_approve(self, db):
        uid, rid = self._ids(db)
        db.create_access_request(uid, rid, justification='Testing')
        req = db.get_access_requests(status_filter='pending')[0]
        db.review_access_request(req['id'], 'approved', reviewed_by='manager', notes='LGTM')
        approved = db.get_access_requests(status_filter='approved')
        assert any(r['id'] == req['id'] for r in approved)

    def test_get_access_requests_filter(self, db):
        uid, rid = self._ids(db)
        db.create_access_request(uid, rid, justification='Test')
        req = db.get_access_requests(status_filter='pending')[0]
        db.review_access_request(req['id'], 'denied', reviewed_by='manager')
        denied = db.get_access_requests(status_filter='denied')
        assert any(r['id'] == req['id'] for r in denied)


# ── Audit log ─────────────────────────────────────────────────────────────────

class TestAuditLog:
    def test_log_audit_info(self, db):
        db.log_audit('tester', 'TEST_ACTION', target_type='test', details='unit test')
        entries = db.get_audit_log(limit=5, search='TEST_ACTION')
        assert any(e['action'] == 'TEST_ACTION' for e in entries)

    def test_log_audit_severity_filter(self, db):
        db.log_audit('tester', 'WARN_EVENT', severity='warning')
        warnings = db.get_audit_log(severity_filter='warning')
        assert all(e['severity'] == 'warning' for e in warnings)

    def test_audit_log_limit(self, db):
        for i in range(20):
            db.log_audit('tester', f'BULK_{i}')
        entries = db.get_audit_log(limit=5)
        assert len(entries) <= 5


# ── Password policy ───────────────────────────────────────────────────────────

class TestPasswordPolicy:
    def test_get_default_policy(self, db):
        policy = db.get_password_policy()
        assert policy['min_length'] == 12
        assert policy['require_uppercase'] == 1

    def test_update_policy(self, db):
        db.update_password_policy(min_length=16, max_age_days=60)
        policy = db.get_password_policy()
        assert policy['min_length'] == 16
        assert policy['max_age_days'] == 60

    def test_update_policy_invalid_col_raises(self, db):
        with pytest.raises(ValueError):
            db.update_password_policy(evil_col='DROP TABLE')


# ── Dashboard stats ───────────────────────────────────────────────────────────

class TestDashboardStats:
    def test_stats_keys_present(self, db):
        stats = db.get_dashboard_stats()
        expected = {'total_users', 'active_users', 'inactive_users', 'locked_users',
                    'pending_review', 'total_roles', 'mfa_enabled', 'mfa_disabled',
                    'pending_requests', 'critical_roles', 'high_risk_roles',
                    'recent_audit_warnings', 'departments', 'role_distribution'}
        assert expected <= set(stats.keys())

    def test_stats_counts_are_nonnegative(self, db):
        stats = db.get_dashboard_stats()
        for key in ('total_users', 'active_users', 'total_roles', 'mfa_enabled'):
            assert stats[key] >= 0

    def test_stats_total_users_matches_seeded(self, db):
        assert db.get_dashboard_stats()['total_users'] == 10


# ── Access reviews ────────────────────────────────────────────────────────────

class TestAccessReviews:
    def test_create_access_review(self, db):
        review_id = db.create_access_review('Q2 2026 Review', reviewer='admin')
        assert isinstance(review_id, int)
        reviews = db.get_access_reviews()
        assert any(r['id'] == review_id for r in reviews)

    def test_review_items_populated(self, db):
        review_id = db.create_access_review('Q2 2026 Review', reviewer='admin')
        items = db.get_review_items(review_id)
        assert len(items) > 0  # seeded user-role assignments should appear

    def test_review_items_have_expected_fields(self, db):
        review_id = db.create_access_review('Test Review', reviewer='admin')
        items = db.get_review_items(review_id)
        for item in items:
            assert 'user_name' in item.keys()
            assert 'role_name' in item.keys()
            assert 'risk_level' in item.keys()
