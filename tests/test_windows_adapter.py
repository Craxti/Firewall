"""
Tests for Windows firewall adapter.
"""
import unittest
import sys
from unittest.mock import patch, MagicMock
from firewall.windows.adapter import WindowsFirewallAdapter


class TestWindowsFirewallAdapter(unittest.TestCase):
    """Tests for WindowsFirewallAdapter."""
    
    def setUp(self):
        """Test setup."""
        self.adapter = WindowsFirewallAdapter(verbose=0, execute=False)
        self.adapter.command_list = []
    
    def test_init(self):
        """Test adapter initialization."""
        self.assertEqual(self.adapter.verbose, 0)
        self.assertFalse(self.adapter.execute)
        self.assertEqual(self.adapter.rule_counter, 0)
        self.assertEqual(len(self.adapter.command_list), 0)
    
    def test_generate_rule_name(self):
        """Test rule name generation."""
        name1 = self.adapter._generate_rule_name("Test")
        name2 = self.adapter._generate_rule_name("Test")
        
        self.assertEqual(name1, "Test_1")
        self.assertEqual(name2, "Test_2")
        self.assertEqual(self.adapter.rule_counter, 2)
    
    def test_flush_rules(self):
        """Test rule cleanup."""
        self.adapter.flush_rules()
        
        self.assertEqual(len(self.adapter.command_list), 1)
        self.assertIn("Remove-NetFirewallRule", self.adapter.command_list[0])
        self.assertIn("FirewallRule_*", self.adapter.command_list[0])
    
    def test_set_policy_accept(self):
        """Test ACCEPT policy setup."""
        rules = self.adapter.set_policy("ACCEPT")
        
        self.assertEqual(len(rules), 2)
        self.assertEqual(len(self.adapter.command_list), 2)
        self.assertTrue(all("Allow" in rule for rule in rules))
    
    def test_set_policy_drop(self):
        """Test DROP policy setup."""
        rules = self.adapter.set_policy("DROP")
        
        self.assertEqual(len(rules), 2)
        self.assertEqual(len(self.adapter.command_list), 2)
        self.assertTrue(all("Block" in rule for rule in rules))
    
    def test_allow_dhcp(self):
        """Test DHCP allowance."""
        self.adapter.allow_dhcp()
        
        self.assertEqual(len(self.adapter.command_list), 2)
        self.assertTrue(any("DHCP_In" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("DHCP_Out" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("UDP" in cmd for cmd in self.adapter.command_list))
    
    def test_allow_ping(self):
        """Test ping allowance."""
        self.adapter.allow_ping()
        
        self.assertEqual(len(self.adapter.command_list), 4)
        self.assertTrue(any("ICMP_In_EchoRequest" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("ICMP_In_EchoReply" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("ICMP_Out_EchoRequest" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("ICMP_Out_EchoReply" in cmd for cmd in self.adapter.command_list))
    
    def test_disallow_ping(self):
        """Test ping blocking."""
        self.adapter.disallow_ping()
        
        self.assertEqual(len(self.adapter.command_list), 1)
        self.assertTrue(any("ICMP_Block_In" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("Block" in cmd for cmd in self.adapter.command_list))
    
    def test_allow_network_transport_tcp(self):
        """Test TCP traffic allowance."""
        self.adapter.allow_network_transport(
            direction='inbound',
            protocol='tcp',
            ports=[80, 443],
            networks=['192.168.1.0/24'],
            policy='ACCEPT'
        )
        
        self.assertEqual(len(self.adapter.command_list), 1)
        cmd = self.adapter.command_list[0]
        self.assertIn("TCP", cmd)
        self.assertIn("Inbound", cmd)
        self.assertIn("80,443", cmd)
        self.assertIn("192.168.1.0/24", cmd)
        self.assertIn("Allow", cmd)
    
    def test_allow_network_transport_udp(self):
        """Test UDP traffic allowance."""
        self.adapter.allow_network_transport(
            direction='outbound',
            protocol='udp',
            ports=[53],
            networks=['8.8.8.8'],
            policy='ACCEPT'
        )
        
        self.assertEqual(len(self.adapter.command_list), 1)
        cmd = self.adapter.command_list[0]
        self.assertIn("UDP", cmd)
        self.assertIn("Outbound", cmd)
        self.assertIn("53", cmd)
        self.assertIn("8.8.8.8", cmd)
        self.assertIn("Allow", cmd)
    
    def test_set_nostrike(self):
        """Test network blocking."""
        networks = ['192.168.1.0/24', '10.0.0.0/8']
        self.adapter.set_nostrike(networks)
        
        self.assertEqual(len(self.adapter.command_list), 4)  # 2 networks * 2 directions
        
        for network in networks:
            self.assertTrue(any(network in cmd for cmd in self.adapter.command_list))
    
    def test_allow_all(self):
        """Test all traffic allowance."""
        self.adapter.allow_all()
        
        # Should have commands for cleanup and ACCEPT policy setup
        self.assertTrue(any("Remove-NetFirewallRule" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("Allow" in cmd for cmd in self.adapter.command_list))
    
    def test_deny_all(self):
        """Test all traffic blocking."""
        self.adapter.deny_all()
        
        # Should have commands for cleanup, DROP policy setup and related connections allowance
        self.assertTrue(any("Remove-NetFirewallRule" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("Block" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("Related" in cmd for cmd in self.adapter.command_list))
    
    def test_invalid_direction(self):
        """Test invalid direction."""
        with self.assertRaises(ValueError):
            self.adapter.allow_network_transport(
                direction='invalid',
                protocol='tcp',
                policy='ACCEPT'
            )
    
    def test_invalid_protocol(self):
        """Test invalid protocol."""
        with self.assertRaises(ValueError):
            self.adapter.allow_network_transport(
                direction='inbound',
                protocol='invalid',
                policy='ACCEPT'
            )


if __name__ == '__main__':
    unittest.main()