"""
Integration tests for firewall.
"""
import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock
from firewall.interact.set_firewall import SetFirewall
from firewall.windows.adapter import WindowsFirewallAdapter
from firewall.host_config.confighost import ConfigHost


class TestFirewallIntegration(unittest.TestCase):
    """Integration tests for firewall."""
    
    def setUp(self):
        """Test setup."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'test_config.ini')
        
        # Create test config
        with open(self.config_file, 'w') as f:
            f.write("""
[local_config]
iface=eth0
rh_host=test-server
rh_ipaddr=192.168.1.100
netmask=255.255.255.0
gateway_addr=192.168.1.1
dns=8.8.8.8
rh_mac=*
cidr_prefix=24
win_host=test-windows
win_ipaddr=192.168.1.101

[firewall_config]
target_range=10.0.0.0/8
trusted_range=192.168.1.0/24
nostrike=192.168.1.5/32
""")
    
    def tearDown(self):
        """Cleanup after tests."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    @patch('firewall.utils.shell.Interact')
    @patch('sys.argv', ['firewall'])
    def test_linux_firewall_basic_setup(self, mock_interact):
        """Test basic Linux firewall setup."""
        mock_interact.return_value.root_check.return_value = None
        
        firewall = SetFirewall(verbose=0, execute=False)
        firewall.flush_rules()
        firewall.allow_dhcp()
        firewall.allow_ping()
        firewall.allow_localhost()
        
        # Check that commands are added
        self.assertGreater(len(firewall.command_list), 0)
        self.assertTrue(any('iptables -F' in cmd for cmd in firewall.command_list))
        self.assertTrue(any('--dport 67:68' in cmd for cmd in firewall.command_list))
        self.assertTrue(any('127.0.0.1/8' in cmd for cmd in firewall.command_list))
    
    def test_windows_firewall_basic_setup(self):
        """Test basic Windows firewall setup."""
        adapter = WindowsFirewallAdapter(verbose=0, execute=False)
        adapter.flush_rules()
        adapter.allow_dhcp()
        adapter.allow_ping()
        adapter.allow_localhost()
        
        # Check that commands are added
        self.assertGreater(len(adapter.command_list), 0)
        self.assertTrue(any('Remove-NetFirewallRule' in cmd for cmd in adapter.command_list))
        self.assertTrue(any('DHCP' in cmd for cmd in adapter.command_list))
        self.assertTrue(any('ICMP' in cmd for cmd in adapter.command_list))
    
    @patch('firewall.utils.shell.Interact')
    @patch('sys.argv', ['firewall'])
    def test_network_transport_rules(self, mock_interact):
        """Test network transport rules."""
        mock_interact.return_value.root_check.return_value = None
        
        firewall = SetFirewall(verbose=0, execute=False)
        
        # Test TCP rules
        firewall.allow_network_transport(
            protocol='tcp',
            direction='inbound',
            ports=[80, 443],
            networks=['192.168.1.0/24'],
            policy='ACCEPT'
        )
        
        # Test UDP rules
        firewall.allow_network_transport(
            protocol='udp',
            direction='outbound',
            ports=[53],
            networks=['8.8.8.8'],
            policy='ACCEPT'
        )
        
        # Check commands
        tcp_commands = [cmd for cmd in firewall.command_list if 'tcp' in cmd.lower()]
        udp_commands = [cmd for cmd in firewall.command_list if 'udp' in cmd.lower()]
        
        self.assertGreater(len(tcp_commands), 0)
        self.assertGreater(len(udp_commands), 0)
        self.assertTrue(any('80,443' in cmd for cmd in tcp_commands))
        self.assertTrue(any('53' in cmd for cmd in udp_commands))
    
    def test_windows_network_transport_rules(self):
        """Test network transport rules for Windows."""
        adapter = WindowsFirewallAdapter(verbose=0, execute=False)
        
        # Test TCP rules
        adapter.allow_network_transport(
            protocol='tcp',
            direction='inbound',
            ports=[80, 443],
            networks=['192.168.1.0/24'],
            policy='ACCEPT'
        )
        
        # Test UDP rules
        adapter.allow_network_transport(
            protocol='udp',
            direction='outbound',
            ports=[53],
            networks=['8.8.8.8'],
            policy='ACCEPT'
        )
        
        # Check commands
        tcp_commands = [cmd for cmd in adapter.command_list if 'TCP' in cmd]
        udp_commands = [cmd for cmd in adapter.command_list if 'UDP' in cmd]
        
        self.assertGreater(len(tcp_commands), 0)
        self.assertGreater(len(udp_commands), 0)
        self.assertTrue(any('80,443' in cmd for cmd in tcp_commands))
        self.assertTrue(any('53' in cmd for cmd in udp_commands))
    
    @patch('firewall.utils.shell.Interact')
    @patch('sys.argv', ['firewall'])
    def test_deny_all_policy(self, mock_interact):
        """Test deny all policy."""
        mock_interact.return_value.root_check.return_value = None
        
        firewall = SetFirewall(verbose=0, execute=False)
        firewall.deny_all()
        
        # Check that DROP policy is set
        self.assertTrue(any('iptables -P' in cmd and 'DROP' in cmd for cmd in firewall.command_list))
        # Check that localhost is allowed
        self.assertTrue(any('127.0.0.1/8' in cmd for cmd in firewall.command_list))
    
    def test_windows_deny_all_policy(self):
        """Test deny all policy for Windows."""
        adapter = WindowsFirewallAdapter(verbose=0, execute=False)
        adapter.deny_all()
        
        # Check that Block policy is set
        self.assertTrue(any('Block' in cmd for cmd in adapter.command_list))
        # Check that related connections are allowed
        self.assertTrue(any('Related' in cmd for cmd in adapter.command_list))
    
    @patch('firewall.utils.shell.Interact')
    @patch('sys.argv', ['firewall'])
    def test_allow_all_policy(self, mock_interact):
        """Test allow all policy."""
        mock_interact.return_value.root_check.return_value = None
        
        firewall = SetFirewall(verbose=0, execute=False)
        firewall.allow_all()
        
        # Check that ACCEPT policy is set
        self.assertTrue(any('iptables -P' in cmd and 'ACCEPT' in cmd for cmd in firewall.command_list))
    
    def test_windows_allow_all_policy(self):
        """Test allow all policy for Windows."""
        adapter = WindowsFirewallAdapter(verbose=0, execute=False)
        adapter.allow_all()
        
        # Check that Allow policy is set
        self.assertTrue(any('Allow' in cmd for cmd in adapter.command_list))
    
    @patch('firewall.utils.shell.Interact')
    @patch('sys.argv', ['firewall'])
    @patch('firewall.utils.shell.Interact.root_check')
    @patch('firewall.base.validation.Validation.eth_iface_check')
    @patch('firewall.utils.shell.Interact.run_command')
    def test_config_host_integration(self, mock_run_command, mock_eth_iface_check, mock_root_check, mock_interact):
        """Test ConfigHost integration."""
        mock_interact.return_value.root_check.return_value = None
        mock_root_check.return_value = None
        mock_eth_iface_check.return_value = True  # Mock eth_iface_check to return True
        mock_run_command.return_value = "eth0\neth1\nwlan0"  # Mock network interfaces
        
        # Create ConfigHost with test config
        config_host = ConfigHost(config_in=self.config_file, VERBOSE=False)
        
        # Check that config is loaded
        self.assertIsNotNone(config_host.set_firewall.config)
        
        # Test value retrieval
        iface = config_host.set_firewall.config.get('local_config', 'iface')
        self.assertEqual(iface, ['eth0'])


if __name__ == '__main__':
    unittest.main()
