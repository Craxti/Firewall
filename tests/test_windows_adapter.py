"""
Тесты для Windows адаптера firewall.
"""
import unittest
import sys
from unittest.mock import patch, MagicMock
from firewall.windows.adapter import WindowsFirewallAdapter


class TestWindowsFirewallAdapter(unittest.TestCase):
    """Тесты для WindowsFirewallAdapter."""
    
    def setUp(self):
        """Настройка тестов."""
        self.adapter = WindowsFirewallAdapter(verbose=0, execute=False)
        self.adapter.command_list = []
    
    def test_init(self):
        """Тест инициализации адаптера."""
        self.assertEqual(self.adapter.verbose, 0)
        self.assertFalse(self.adapter.execute)
        self.assertEqual(self.adapter.rule_counter, 0)
        self.assertEqual(len(self.adapter.command_list), 0)
    
    def test_generate_rule_name(self):
        """Тест генерации имен правил."""
        name1 = self.adapter._generate_rule_name("Test")
        name2 = self.adapter._generate_rule_name("Test")
        
        self.assertEqual(name1, "Test_1")
        self.assertEqual(name2, "Test_2")
        self.assertEqual(self.adapter.rule_counter, 2)
    
    def test_flush_rules(self):
        """Тест очистки правил."""
        self.adapter.flush_rules()
        
        self.assertEqual(len(self.adapter.command_list), 1)
        self.assertIn("Remove-NetFirewallRule", self.adapter.command_list[0])
        self.assertIn("FirewallRule_*", self.adapter.command_list[0])
    
    def test_set_policy_accept(self):
        """Тест установки политики ACCEPT."""
        rules = self.adapter.set_policy("ACCEPT")
        
        self.assertEqual(len(rules), 2)
        self.assertEqual(len(self.adapter.command_list), 2)
        self.assertTrue(all("Allow" in rule for rule in rules))
    
    def test_set_policy_drop(self):
        """Тест установки политики DROP."""
        rules = self.adapter.set_policy("DROP")
        
        self.assertEqual(len(rules), 2)
        self.assertEqual(len(self.adapter.command_list), 2)
        self.assertTrue(all("Block" in rule for rule in rules))
    
    def test_allow_dhcp(self):
        """Тест разрешения DHCP."""
        self.adapter.allow_dhcp()
        
        self.assertEqual(len(self.adapter.command_list), 2)
        self.assertTrue(any("DHCP_In" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("DHCP_Out" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("UDP" in cmd for cmd in self.adapter.command_list))
    
    def test_allow_ping(self):
        """Тест разрешения ping."""
        self.adapter.allow_ping()
        
        self.assertEqual(len(self.adapter.command_list), 4)
        self.assertTrue(any("ICMP_In_EchoRequest" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("ICMP_In_EchoReply" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("ICMP_Out_EchoRequest" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("ICMP_Out_EchoReply" in cmd for cmd in self.adapter.command_list))
    
    def test_disallow_ping(self):
        """Тест блокировки ping."""
        self.adapter.disallow_ping()
        
        self.assertEqual(len(self.adapter.command_list), 1)
        self.assertTrue(any("ICMP_Block_In" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("Block" in cmd for cmd in self.adapter.command_list))
    
    def test_allow_network_transport_tcp(self):
        """Тест разрешения TCP трафика."""
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
        """Тест разрешения UDP трафика."""
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
        """Тест блокировки сетей."""
        networks = ['192.168.1.0/24', '10.0.0.0/8']
        self.adapter.set_nostrike(networks)
        
        self.assertEqual(len(self.adapter.command_list), 4)  # 2 сети * 2 направления
        
        for network in networks:
            self.assertTrue(any(network in cmd for cmd in self.adapter.command_list))
    
    def test_allow_all(self):
        """Тест разрешения всего трафика."""
        self.adapter.allow_all()
        
        # Должны быть команды для очистки и установки политики ACCEPT
        self.assertTrue(any("Remove-NetFirewallRule" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("Allow" in cmd for cmd in self.adapter.command_list))
    
    def test_deny_all(self):
        """Тест блокировки всего трафика."""
        self.adapter.deny_all()
        
        # Должны быть команды для очистки, установки политики DROP и разрешения связанных соединений
        self.assertTrue(any("Remove-NetFirewallRule" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("Block" in cmd for cmd in self.adapter.command_list))
        self.assertTrue(any("Related" in cmd for cmd in self.adapter.command_list))
    
    def test_invalid_direction(self):
        """Тест неверного направления."""
        with self.assertRaises(ValueError):
            self.adapter.allow_network_transport(
                direction='invalid',
                protocol='tcp',
                policy='ACCEPT'
            )
    
    def test_invalid_protocol(self):
        """Тест неверного протокола."""
        with self.assertRaises(ValueError):
            self.adapter.allow_network_transport(
                direction='inbound',
                protocol='invalid',
                policy='ACCEPT'
            )


if __name__ == '__main__':
    unittest.main()