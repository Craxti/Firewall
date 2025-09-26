import unittest
import sys
from unittest.mock import patch, MagicMock
from firewall.interact.set_firewall import SetFirewall


class TestSetFirewall(unittest.TestCase):
    
    @patch('firewall.utils.shell.Interact')
    @patch('sys.argv', ['firewall'])
    def setUp(self, mock_interact):
        self.mock_interact = mock_interact
        self.mock_interact.return_value.root_check.return_value = None
        
        def side_effect(*args, **kwargs):
            return None
        self.mock_interact.return_value.root_check.side_effect = side_effect
        
        self.firewall = SetFirewall(verbose=0, execute=False)
        self.firewall.command_list = []
    
    def test_flush_rules(self):
        """Test flush_rules method correctly adds flush commands"""
        self.firewall.flush_rules()
        self.assertEqual(len(self.firewall.command_list), 3)
        self.assertTrue(all(['iptables -F' in cmd for cmd in self.firewall.command_list]))
    
    def test_allow_dhcp(self):
        """Test allow_dhcp method correctly adds DHCP allow rules"""
        self.firewall.allow_dhcp()
        self.assertEqual(len(self.firewall.command_list), 2)
        self.assertTrue(all(['--dport 67:68 --sport 67:68 -j ACCEPT' in cmd for cmd in self.firewall.command_list]))
    
    def test_allow_localhost(self):
        """Test allow_localhost method correctly adds localhost rules"""
        self.firewall.allow_localhost()
        self.assertEqual(len(self.firewall.command_list), 2)
        self.assertTrue(all(['127.0.0.1/8' in cmd for cmd in self.firewall.command_list]))
    
    def test_network_validator_valid(self):
        """Test network_validator accepts valid networks"""
        result = self.firewall.network_validator('192.168.1.0/24')
        self.assertTrue(result)
    
    @patch('firewall.interact.set_firewall.ipaddr.IPNetwork')
    def test_network_validator_invalid(self, mock_ipnetwork):
        """Test network_validator rejects invalid networks"""
        mock_ipnetwork.side_effect = Exception("Invalid network")
        with self.assertRaises(Exception):
            self.firewall.network_validator('invalid_network')
            
    def test_set_policy(self):
        """Test set_policy method correctly adds policy rules"""
        rules = self.firewall.set_policy('DROP')
        self.assertEqual(len(rules), 3)
        self.assertTrue(all(['iptables -P' in cmd for cmd in rules]))
        self.assertTrue(all(['DROP' in cmd for cmd in rules]))
        
    def test_allow_all(self):
        """Test allow_all method correctly sets ACCEPT policy"""
        self.firewall.allow_all()
        # Check that rules are flushed and ACCEPT policy is set
        self.assertTrue(any(['iptables -F' in cmd for cmd in self.firewall.command_list]))
        self.assertTrue(any(['iptables -P' in cmd and 'ACCEPT' in cmd for cmd in self.firewall.command_list]))
        
    def test_deny_all(self):
        """Test deny_all method correctly sets DROP policy"""
        self.firewall.deny_all()
        # Check that DROP policy is set and localhost is allowed
        self.assertTrue(any(['iptables -P' in cmd and 'DROP' in cmd for cmd in self.firewall.command_list]))
        self.assertTrue(any(['127.0.0.1/8' in cmd for cmd in self.firewall.command_list]))
        
    def test_disallow_ping(self):
        """Test disallow_ping method correctly adds ping blocking rules"""
        self.firewall.disallow_ping()
        self.assertEqual(len(self.firewall.command_list), 1)
        self.assertTrue(all(['icmp --icmp-type 8 -j DROP' in cmd for cmd in self.firewall.command_list]))
        
    def test_allow_ping(self):
        """Test allow_ping method correctly adds ping allow rules"""
        self.firewall.allow_ping()
        self.assertEqual(len(self.firewall.command_list), 4)
        # Check for rules for icmp type 0 and 8 on input and output
        icmp_types = [cmd for cmd in self.firewall.command_list if 'icmp' in cmd]
        self.assertEqual(len(icmp_types), 4)
        
    def test_set_nostrike(self):
        """Test set_nostrike method correctly adds drop rules for specified networks"""
        networks = ['192.168.1.0/24', '10.0.0.0/8']
        self.firewall.set_nostrike(networks)
        # Should be 4 rules (2 per network - for INPUT and OUTPUT)
        self.assertEqual(len(self.firewall.command_list), 4)
        # Check that all networks are included in rules
        for network in networks:
            self.assertTrue(any([network in cmd for cmd in self.firewall.command_list]))
            
    def test_allow_related_conn(self):
        """Test allow_related_conn method correctly adds connection tracking rules"""
        self.firewall.allow_related_conn()
        self.assertEqual(len(self.firewall.command_list), 2)
        self.assertTrue(all(['--ctstate ESTABLISHED,RELATED' in cmd for cmd in self.firewall.command_list]))
        
    def test_data_validator(self):
        """Test data_validator correctly handles strings and lists"""
        # String check
        result = self.firewall.data_validator('192.168.1.0/24')
        self.assertIsInstance(result, list)
        self.assertEqual(result, ['192.168.1.0/24'])
        
        # List check
        input_list = ['192.168.1.0/24', '10.0.0.0/8']
        result = self.firewall.data_validator(input_list)
        self.assertEqual(result, input_list)


if __name__ == '__main__':
    unittest.main() 