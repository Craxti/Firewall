import unittest
from unittest.mock import patch, MagicMock, call
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from firewall.windows.adapter import WindowsFirewallAdapter


class TestWindowsFirewallAdapter(unittest.TestCase):
    
    def setUp(self):
        self.adapter = WindowsFirewallAdapter(verbose=0)
        self.adapter.command_list = []
    
    @patch('subprocess.check_output')
    def test_run_command(self, mock_check_output):
        """Test that run_command correctly executes PowerShell commands"""
        mock_check_output.return_value = b"command output"
        
        result = self.adapter.run_command("Get-NetFirewallRule")
        
        mock_check_output.assert_called_once()
        args, kwargs = mock_check_output.call_args
        self.assertTrue('powershell.exe' in args[0])
        self.assertTrue('Get-NetFirewallRule' in args[0])
        
        self.assertEqual(result, "command output")
    
    @patch('firewall.windows.adapter.WindowsFirewallAdapter.run_command')
    def test_flush_rules(self, mock_run_command):
        """Test that flush_rules correctly creates PowerShell commands to remove rules"""
        self.adapter.flush_rules()
        
        self.assertTrue(len(self.adapter.command_list) > 0)
        for cmd in self.adapter.command_list:
            self.assertTrue('Remove-NetFirewallRule' in cmd)
    
    @patch('firewall.windows.adapter.WindowsFirewallAdapter.run_command')
    def test_allow_dhcp(self, mock_run_command):
        """Test that allow_dhcp creates correct rules for DHCP in Windows"""
        self.adapter.allow_dhcp()
        
        self.assertTrue(len(self.adapter.command_list) > 0)
        dhcp_commands = [cmd for cmd in self.adapter.command_list if '67' in cmd or '68' in cmd]
        self.assertTrue(len(dhcp_commands) > 0)
    
    @patch('firewall.windows.adapter.WindowsFirewallAdapter.run_command')
    def test_allow_ping(self, mock_run_command):
        """Test that allow_ping creates rules for ICMP in Windows"""
        self.adapter.allow_ping()
        
        self.assertTrue(len(self.adapter.command_list) > 0)
        icmp_commands = [cmd for cmd in self.adapter.command_list if 'ICMPv4' in cmd]
        self.assertTrue(len(icmp_commands) > 0)
    
    @patch('firewall.windows.adapter.WindowsFirewallAdapter.run_command')
    def test_allow_network_transport(self, mock_run_command):
        """Test that allow_network_transport creates rules for ports and protocols"""
        self.adapter.allow_network_transport(
            direction='inbound',
            protocol='tcp',
            ports=['80'],
            networks='192.168.1.0/24'
        )
        
        self.assertTrue(len(self.adapter.command_list) > 0)
        for cmd in self.adapter.command_list:
            self.assertTrue('New-NetFirewallRule' in cmd)
            self.assertTrue('LocalPort 80' in cmd or 'RemotePort 80' in cmd)
            self.assertTrue('192.168.1.0/24' in cmd)
            self.assertTrue('Protocol TCP' in cmd)
    
    @patch('firewall.windows.adapter.WindowsFirewallAdapter.run_command')
    def test_process_commands(self, mock_run_command):
        """Test that process_commands executes all commands in command_list"""
        test_commands = [
            "New-NetFirewallRule -Name 'Test1'",
            "New-NetFirewallRule -Name 'Test2'"
        ]
        self.adapter.command_list = test_commands
        
        self.adapter.process_commands()
        
        self.assertEqual(mock_run_command.call_count, len(test_commands))
        for cmd in test_commands:
            mock_run_command.assert_any_call(cmd)


if __name__ == '__main__':
    unittest.main() 