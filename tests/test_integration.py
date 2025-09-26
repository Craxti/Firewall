"""
Интеграционные тесты для firewall.
"""
import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock
from firewall.interact.set_firewall import SetFirewall
from firewall.windows.adapter import WindowsFirewallAdapter
from firewall.host_config.confighost import ConfigHost


class TestFirewallIntegration(unittest.TestCase):
    """Интеграционные тесты для firewall."""
    
    def setUp(self):
        """Настройка тестов."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'test_config.ini')
        
        # Создаем тестовый конфиг
        with open(self.config_file, 'w') as f:
            f.write("""
[local_config]
iface=eth0
rh_host=test-server
rh_ipaddr=192.168.1.100
netmask=255.255.255.0
gateway_addr=192.168.1.1
dns=8.8.8.8

[firewall_config]
target_range=10.0.0.0/8
trusted_range=192.168.1.0/24
nostrike=192.168.1.5/32
""")
    
    def tearDown(self):
        """Очистка после тестов."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    @patch('firewall.utils.shell.Interact')
    @patch('sys.argv', ['firewall'])
    def test_linux_firewall_basic_setup(self, mock_interact):
        """Тест базовой настройки Linux firewall."""
        mock_interact.return_value.root_check.return_value = None
        
        firewall = SetFirewall(verbose=0, execute=False)
        firewall.flush_rules()
        firewall.allow_dhcp()
        firewall.allow_ping()
        firewall.allow_localhost()
        
        # Проверяем, что команды добавлены
        self.assertGreater(len(firewall.command_list), 0)
        self.assertTrue(any('iptables -F' in cmd for cmd in firewall.command_list))
        self.assertTrue(any('--dport 67:68' in cmd for cmd in firewall.command_list))
        self.assertTrue(any('127.0.0.1/8' in cmd for cmd in firewall.command_list))
    
    def test_windows_firewall_basic_setup(self):
        """Тест базовой настройки Windows firewall."""
        adapter = WindowsFirewallAdapter(verbose=0, execute=False)
        adapter.flush_rules()
        adapter.allow_dhcp()
        adapter.allow_ping()
        adapter.allow_localhost()
        
        # Проверяем, что команды добавлены
        self.assertGreater(len(adapter.command_list), 0)
        self.assertTrue(any('Remove-NetFirewallRule' in cmd for cmd in adapter.command_list))
        self.assertTrue(any('DHCP' in cmd for cmd in adapter.command_list))
        self.assertTrue(any('ICMP' in cmd for cmd in adapter.command_list))
    
    @patch('firewall.utils.shell.Interact')
    @patch('sys.argv', ['firewall'])
    def test_network_transport_rules(self, mock_interact):
        """Тест правил сетевого транспорта."""
        mock_interact.return_value.root_check.return_value = None
        
        firewall = SetFirewall(verbose=0, execute=False)
        
        # Тест TCP правил
        firewall.allow_network_transport(
            protocol='tcp',
            direction='inbound',
            ports=[80, 443],
            networks=['192.168.1.0/24'],
            policy='ACCEPT'
        )
        
        # Тест UDP правил
        firewall.allow_network_transport(
            protocol='udp',
            direction='outbound',
            ports=[53],
            networks=['8.8.8.8'],
            policy='ACCEPT'
        )
        
        # Проверяем команды
        tcp_commands = [cmd for cmd in firewall.command_list if 'tcp' in cmd.lower()]
        udp_commands = [cmd for cmd in firewall.command_list if 'udp' in cmd.lower()]
        
        self.assertGreater(len(tcp_commands), 0)
        self.assertGreater(len(udp_commands), 0)
        self.assertTrue(any('80,443' in cmd for cmd in tcp_commands))
        self.assertTrue(any('53' in cmd for cmd in udp_commands))
    
    def test_windows_network_transport_rules(self):
        """Тест правил сетевого транспорта для Windows."""
        adapter = WindowsFirewallAdapter(verbose=0, execute=False)
        
        # Тест TCP правил
        adapter.allow_network_transport(
            protocol='tcp',
            direction='inbound',
            ports=[80, 443],
            networks=['192.168.1.0/24'],
            policy='ACCEPT'
        )
        
        # Тест UDP правил
        adapter.allow_network_transport(
            protocol='udp',
            direction='outbound',
            ports=[53],
            networks=['8.8.8.8'],
            policy='ACCEPT'
        )
        
        # Проверяем команды
        tcp_commands = [cmd for cmd in adapter.command_list if 'TCP' in cmd]
        udp_commands = [cmd for cmd in adapter.command_list if 'UDP' in cmd]
        
        self.assertGreater(len(tcp_commands), 0)
        self.assertGreater(len(udp_commands), 0)
        self.assertTrue(any('80,443' in cmd for cmd in tcp_commands))
        self.assertTrue(any('53' in cmd for cmd in udp_commands))
    
    @patch('firewall.utils.shell.Interact')
    @patch('sys.argv', ['firewall'])
    def test_deny_all_policy(self, mock_interact):
        """Тест политики deny all."""
        mock_interact.return_value.root_check.return_value = None
        
        firewall = SetFirewall(verbose=0, execute=False)
        firewall.deny_all()
        
        # Проверяем, что установлена политика DROP
        self.assertTrue(any('iptables -P' in cmd and 'DROP' in cmd for cmd in firewall.command_list))
        # Проверяем, что разрешен localhost
        self.assertTrue(any('127.0.0.1/8' in cmd for cmd in firewall.command_list))
    
    def test_windows_deny_all_policy(self):
        """Тест политики deny all для Windows."""
        adapter = WindowsFirewallAdapter(verbose=0, execute=False)
        adapter.deny_all()
        
        # Проверяем, что установлена политика Block
        self.assertTrue(any('Block' in cmd for cmd in adapter.command_list))
        # Проверяем, что разрешены связанные соединения
        self.assertTrue(any('Related' in cmd for cmd in adapter.command_list))
    
    @patch('firewall.utils.shell.Interact')
    @patch('sys.argv', ['firewall'])
    def test_allow_all_policy(self, mock_interact):
        """Тест политики allow all."""
        mock_interact.return_value.root_check.return_value = None
        
        firewall = SetFirewall(verbose=0, execute=False)
        firewall.allow_all()
        
        # Проверяем, что установлена политика ACCEPT
        self.assertTrue(any('iptables -P' in cmd and 'ACCEPT' in cmd for cmd in firewall.command_list))
    
    def test_windows_allow_all_policy(self):
        """Тест политики allow all для Windows."""
        adapter = WindowsFirewallAdapter(verbose=0, execute=False)
        adapter.allow_all()
        
        # Проверяем, что установлена политика Allow
        self.assertTrue(any('Allow' in cmd for cmd in adapter.command_list))
    
    @patch('firewall.utils.shell.Interact')
    @patch('sys.argv', ['firewall'])
    @patch('firewall.utils.shell.Interact.root_check')
    def test_config_host_integration(self, mock_root_check, mock_interact):
        """Тест интеграции с ConfigHost."""
        mock_interact.return_value.root_check.return_value = None
        mock_root_check.return_value = None
        
        # Создаем ConfigHost с тестовым конфигом
        config_host = ConfigHost(config_in=self.config_file, VERBOSE=False)
        
        # Проверяем, что конфиг загружен
        self.assertIsNotNone(config_host.set_firewall.config)
        
        # Тестируем получение значений
        iface = config_host.set_firewall.config.get('local_config', 'iface')
        self.assertEqual(iface, ['eth0'])


if __name__ == '__main__':
    unittest.main()
