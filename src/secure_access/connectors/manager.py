"""
Connector manager — re-exported from root connectors module.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from connectors import ConnectorManager, CONNECTORS  # noqa: E402, F401

__all__ = ["ConnectorManager", "CONNECTORS"]
