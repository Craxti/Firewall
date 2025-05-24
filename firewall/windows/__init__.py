"""
Windows implementation of firewall management.

This module provides adapter for Windows Firewall management
through PowerShell commands that are compatible with the Linux interface.
"""

from .adapter import WindowsFirewallAdapter

__all__ = ['WindowsFirewallAdapter'] 