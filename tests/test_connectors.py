"""Tests for the connector modules."""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from connectors import (
    BaseConnector,
    ProvisioningResult,
    ActiveDirectoryConnector,
    AzureADConnector,
    CONNECTORS,
    ConnectorManager,
)


class TestProvisioningResult:
    """Tests for ProvisioningResult dataclass."""

    def test_successful_result(self):
        result = ProvisioningResult(
            success=True,
            connector="test",
            action="create_user",
            target_user="testuser",
            details="User created",
        )
        assert result.success is True
        assert result.connector == "test"
        assert result.error is None

    def test_failed_result(self):
        result = ProvisioningResult(
            success=False,
            connector="test",
            action="create_user",
            target_user="testuser",
            details="Failed",
            error="Connection refused",
        )
        assert result.success is False
        assert result.error == "Connection refused"

    def test_to_dict(self):
        result = ProvisioningResult(
            success=True,
            connector="test",
            action="test_connection",
            target_user="",
            details="OK",
        )
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["success"] is True
        assert "timestamp" in d


class TestActiveDirectoryConnector:
    """Tests for ActiveDirectoryConnector."""

    def test_connection_fails_without_server(self):
        connector = ActiveDirectoryConnector(config={})
        result = connector.test_connection()
        assert result.success is False
        assert result.error is not None

    def test_connection_succeeds_with_server(self):
        connector = ActiveDirectoryConnector(config={"server": "dc01.example.com"})
        result = connector.test_connection()
        assert result.success is True

    def test_create_user(self):
        connector = ActiveDirectoryConnector(config={"server": "dc01.example.com"})
        result = connector.create_user("jdoe", "John Doe", "jdoe@example.com")
        assert result.success is True
        assert result.target_user == "jdoe"

    def test_disable_user(self):
        connector = ActiveDirectoryConnector(config={"server": "dc01.example.com"})
        result = connector.disable_user("jdoe")
        assert result.success is True

    def test_enable_user(self):
        connector = ActiveDirectoryConnector(config={"server": "dc01.example.com"})
        result = connector.enable_user("jdoe")
        assert result.success is True

    def test_assign_group(self):
        connector = ActiveDirectoryConnector(config={"server": "dc01.example.com"})
        result = connector.assign_group("jdoe", "IT Security")
        assert result.success is True

    def test_remove_group(self):
        connector = ActiveDirectoryConnector(config={"server": "dc01.example.com"})
        result = connector.remove_group("jdoe", "IT Security")
        assert result.success is True

    def test_reset_password(self):
        connector = ActiveDirectoryConnector(config={"server": "dc01.example.com"})
        result = connector.reset_password("jdoe")
        assert result.success is True


class TestAzureADConnector:
    """Tests for AzureADConnector."""

    def test_connection_fails_without_tenant(self):
        connector = AzureADConnector(config={})
        result = connector.test_connection()
        assert result.success is False

    def test_connection_succeeds_with_tenant(self):
        connector = AzureADConnector(config={
            "tenant_id": "abc123",
            "client_id": "def456",
        })
        result = connector.test_connection()
        assert result.success is True


class TestConnectors:
    """Tests for CONNECTORS registry."""

    def test_connectors_list_not_empty(self):
        assert len(CONNECTORS) > 0

    def test_connectors_are_base_connector_subclasses(self):
        for connector_cls in CONNECTORS.values():
            assert issubclass(connector_cls, BaseConnector)

    def test_connector_has_required_attributes(self):
        for connector_cls in CONNECTORS.values():
            assert hasattr(connector_cls, "name")
            assert hasattr(connector_cls, "display_name")
            assert hasattr(connector_cls, "icon")
            assert hasattr(connector_cls, "description")


class TestConnectorManager:
    """Tests for ConnectorManager."""

    def test_manager_initializes(self, tmp_path):
        from database import Database
        db_path = str(tmp_path / "test.db")
        db = Database(db_path=db_path)
        mgr = ConnectorManager(db)
        assert mgr is not None
        db.conn.close()
