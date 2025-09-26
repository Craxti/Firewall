#!/usr/bin/env python3
"""
Tests for firewall.base.cli_parser module.
"""

import pytest
import argparse
from unittest.mock import patch, MagicMock
from firewall.base.cli_parser import BwCli


class TestBwCli:
    """Test BwCli class."""
    
    def test_bwcli_initialization_default(self):
        """Test BwCli initialization with default values."""
        cli = BwCli()
        assert cli.verbose is True
        assert cli.parser is not None
        assert isinstance(cli.parser, argparse.ArgumentParser)
    
    def test_bwcli_initialization_custom(self):
        """Test BwCli initialization with custom values."""
        cli = BwCli(verbose=False)
        assert cli.verbose is False
        assert cli.parser is not None
    
    def test_bwcli_help_defaults(self):
        """Test BwCli help defaults."""
        cli = BwCli()
        assert "Outbound connections will be allowed" in cli.help_defaults
        assert "Inbound connections will be limited" in cli.help_defaults
        assert "DHCP will be enabled" in cli.help_defaults
        assert "Ping responses will be enabled" in cli.help_defaults
        assert "Unsolicited inbound connections will be dropped" in cli.help_defaults
    
    def test_bwcli_about(self):
        """Test BwCli about information."""
        cli = BwCli()
        assert "Version: firewall 3.0" in cli.about
        assert "Authors: Alexksandr Fetisov" in cli.about
        assert "Email: fetis.dev@gmail.com" in cli.about
    
    def test_bwcli_logo(self):
        """Test BwCli logo."""
        cli = BwCli()
        assert cli.logo == "Firewall"


class TestBwCliParser:
    """Test BwCli parser functionality."""
    
    def test_parser_creation(self):
        """Test parser creation."""
        cli = BwCli()
        parser = cli.parser
        
        assert parser is not None
        assert isinstance(parser, argparse.ArgumentParser)
    
    def test_parser_description(self):
        """Test parser description."""
        cli = BwCli()
        parser = cli.parser
        
        assert "python framework to automate firewall setup" in parser.description
        assert "Outbound connections will be allowed" in parser.description
    
    def test_parser_formatter(self):
        """Test parser formatter."""
        cli = BwCli()
        parser = cli.parser
        
        assert parser.formatter_class == argparse.RawDescriptionHelpFormatter


class TestBwCliArguments:
    """Test BwCli command line arguments."""
    
    def test_version_argument(self):
        """Test version argument."""
        cli = BwCli()
        parser = cli.parser
        
        # Test that version argument exists and causes SystemExit
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(['--version'])
        assert exc_info.value.code == 0
    
    def test_verbose_argument(self):
        """Test verbose argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--verbose'])
        assert args.verbose is True
        
        args = parser.parse_args([])
        assert args.verbose is False
    
    def test_reset_argument(self):
        """Test reset argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--reset'])
        assert args.reset is True
        
        args = parser.parse_args([])
        assert args.reset is False
    
    def test_disallow_ping_argument(self):
        """Test disallow_ping argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--disallow_ping'])
        assert args.disallow_ping is True
        
        args = parser.parse_args([])
        assert args.disallow_ping is False
    
    def test_allow_outbound_icmp_argument(self):
        """Test allow_outbound_icmp argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--allow_outbound_icmp'])
        assert args.allow_outbound_icmp is True
        
        args = parser.parse_args([])
        assert args.allow_outbound_icmp is False
    
    def test_disallow_dhcp_argument(self):
        """Test disallow_dhcp argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--disallow_dhcp'])
        assert args.disallow_dhcp is True
        
        args = parser.parse_args([])
        assert args.disallow_dhcp is False
    
    def test_windows_config_argument(self):
        """Test windows_config argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--windows_config', 'config.ps1'])
        assert args.windows_config == 'config.ps1'
        
        args = parser.parse_args([])
        assert args.windows_config is None
    
    def test_tcp_ports_out_argument(self):
        """Test tcp_ports_out argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--tcp_ports_out', '80,443'])
        assert args.tcp_ports_out == '80,443'
        
        args = parser.parse_args([])
        assert args.tcp_ports_out is None
    
    def test_udp_ports_out_argument(self):
        """Test udp_ports_out argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--udp_ports_out', '53,67'])
        assert args.udp_ports_out == '53,67'
        
        args = parser.parse_args([])
        assert args.udp_ports_out is None
    
    def test_tcp_ports_in_argument(self):
        """Test tcp_ports_in argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--tcp_ports_in', '22,3389'])
        assert args.tcp_ports_in == '22,3389'
        
        args = parser.parse_args([])
        assert args.tcp_ports_in is None
    
    def test_udp_ports_in_argument(self):
        """Test udp_ports_in argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--udp_ports_in', '53,67'])
        assert args.udp_ports_in == '53,67'
        
        args = parser.parse_args([])
        assert args.udp_ports_in is None
    
    def test_outbound_hosts_argument(self):
        """Test outbound_hosts argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--outbound_hosts', '192.168.1.0/24,192.168.2.0/24'])
        assert args.outbound_hosts == '192.168.1.0/24,192.168.2.0/24'
        
        args = parser.parse_args([])
        assert args.outbound_hosts is None
    
    def test_inbound_hosts_argument(self):
        """Test inbound_hosts argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--inbound_hosts', '192.168.1.0/24,192.168.2.0/24'])
        assert args.inbound_hosts == '192.168.1.0/24,192.168.2.0/24'
        
        args = parser.parse_args([])
        assert args.inbound_hosts is None
    
    def test_exclude_hosts_argument(self):
        """Test exclude_hosts argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--exclude_hosts', '192.168.1.100,192.168.1.101'])
        assert args.exclude_hosts == '192.168.1.100,192.168.1.101'
        
        args = parser.parse_args([])
        assert args.exclude_hosts is None
    
    def test_log_exceptions_argument(self):
        """Test log_exceptions argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--log_exceptions'])
        assert args.log_exceptions is True
        
        args = parser.parse_args([])
        assert args.log_exceptions is False
    
    def test_simulate_argument(self):
        """Test simulate argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--simulate'])
        assert args.simulate is True
        
        args = parser.parse_args([])
        assert args.simulate is False
    
    def test_quiet_argument(self):
        """Test quiet argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--quiet'])
        assert args.quiet is True
        
        args = parser.parse_args([])
        assert args.quiet is False
    
    def test_deny_all_argument(self):
        """Test deny_all argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--deny_all'])
        assert args.deny_all is True
        
        args = parser.parse_args([])
        assert args.deny_all is False
    
    def test_allow_all_argument(self):
        """Test allow_all argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--allow_all'])
        assert args.allow_all is True
        
        args = parser.parse_args([])
        assert args.allow_all is False
    
    def test_flush_argument(self):
        """Test flush argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--flush'])
        assert args.flush is True
        
        args = parser.parse_args([])
        assert args.flush is False
    
    def test_show_rules_argument(self):
        """Test show_rules argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--show_rules'])
        assert args.show_rules is True
        
        args = parser.parse_args([])
        assert args.show_rules is False
    
    def test_wizard_argument(self):
        """Test wizard argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--wizard'])
        assert args.wizard is True
        
        args = parser.parse_args([])
        assert args.wizard is False
    
    def test_config_argument(self):
        """Test config argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--config', 'config.ini'])
        assert args.config == 'config.ini'
        
        args = parser.parse_args([])
        assert args.config is None


class TestBwCliShortArguments:
    """Test BwCli short command line arguments."""
    
    def test_short_verbose_argument(self):
        """Test short verbose argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-v'])
        assert args.verbose is True
    
    def test_short_reset_argument(self):
        """Test short reset argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-r'])
        assert args.reset is True
    
    def test_short_disallow_ping_argument(self):
        """Test short disallow_ping argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-p'])
        assert args.disallow_ping is True
    
    def test_short_allow_outbound_icmp_argument(self):
        """Test short allow_outbound_icmp argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-i'])
        assert args.allow_outbound_icmp is True
    
    def test_short_disallow_dhcp_argument(self):
        """Test short disallow_dhcp argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-d'])
        assert args.disallow_dhcp is True
    
    def test_short_windows_config_argument(self):
        """Test short windows_config argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-w', 'config.ps1'])
        assert args.windows_config == 'config.ps1'
    
    def test_short_tcp_ports_out_argument(self):
        """Test short tcp_ports_out argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-ot', '80,443'])
        assert args.tcp_ports_out == '80,443'
    
    def test_short_udp_ports_out_argument(self):
        """Test short udp_ports_out argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-ou', '53,67'])
        assert args.udp_ports_out == '53,67'
    
    def test_short_tcp_ports_in_argument(self):
        """Test short tcp_ports_in argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-it', '22,3389'])
        assert args.tcp_ports_in == '22,3389'
    
    def test_short_udp_ports_in_argument(self):
        """Test short udp_ports_in argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-iu', '53,67'])
        assert args.udp_ports_in == '53,67'
    
    def test_short_outbound_hosts_argument(self):
        """Test short outbound_hosts argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-oh', '192.168.1.0/24,192.168.2.0/24'])
        assert args.outbound_hosts == '192.168.1.0/24,192.168.2.0/24'
    
    def test_short_inbound_hosts_argument(self):
        """Test short inbound_hosts argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-ih', '192.168.1.0/24,192.168.2.0/24'])
        assert args.inbound_hosts == '192.168.1.0/24,192.168.2.0/24'
    
    def test_short_exclude_hosts_argument(self):
        """Test short exclude_hosts argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-eh', '192.168.1.100,192.168.1.101'])
        assert args.exclude_hosts == '192.168.1.100,192.168.1.101'
    
    def test_short_log_exceptions_argument(self):
        """Test short log_exceptions argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-l'])
        assert args.log_exceptions is True
    
    def test_short_simulate_argument(self):
        """Test short simulate argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-s'])
        assert args.simulate is True
    
    def test_short_quiet_argument(self):
        """Test short quiet argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-q'])
        assert args.quiet is True
    
    def test_short_deny_all_argument(self):
        """Test short deny_all argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-D'])
        assert args.deny_all is True
    
    def test_short_allow_all_argument(self):
        """Test short allow_all argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-A'])
        assert args.allow_all is True
    
    def test_short_flush_argument(self):
        """Test short flush argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-F'])
        assert args.flush is True
    
    def test_short_show_rules_argument(self):
        """Test short show_rules argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-S'])
        assert args.show_rules is True
    
    def test_short_config_argument(self):
        """Test short config argument."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-c', 'config.ini'])
        assert args.config == 'config.ini'


class TestBwCliComplexArguments:
    """Test BwCli complex argument combinations."""
    
    def test_multiple_boolean_arguments(self):
        """Test multiple boolean arguments."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-v', '-r', '-p', '-i', '-d', '-l', '-s', '-q', '-D', '-A', '-F', '-S', '--wizard'])
        assert args.verbose is True
        assert args.reset is True
        assert args.disallow_ping is True
        assert args.allow_outbound_icmp is True
        assert args.disallow_dhcp is True
        assert args.log_exceptions is True
        assert args.simulate is True
        assert args.quiet is True
        assert args.deny_all is True
        assert args.allow_all is True
        assert args.flush is True
        assert args.show_rules is True
        assert args.wizard is True
    
    def test_multiple_string_arguments(self):
        """Test multiple string arguments."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args([
            '--windows_config', 'config.ps1',
            '--tcp_ports_out', '80,443',
            '--udp_ports_out', '53,67',
            '--tcp_ports_in', '22,3389',
            '--udp_ports_in', '53,67',
            '--outbound_hosts', '192.168.1.0/24,192.168.2.0/24',
            '--inbound_hosts', '192.168.3.0/24,192.168.4.0/24',
            '--exclude_hosts', '192.168.1.100,192.168.1.101',
            '--config', 'config.ini'
        ])
        assert args.windows_config == 'config.ps1'
        assert args.tcp_ports_out == '80,443'
        assert args.udp_ports_out == '53,67'
        assert args.tcp_ports_in == '22,3389'
        assert args.udp_ports_in == '53,67'
        assert args.outbound_hosts == '192.168.1.0/24,192.168.2.0/24'
        assert args.inbound_hosts == '192.168.3.0/24,192.168.4.0/24'
        assert args.exclude_hosts == '192.168.1.100,192.168.1.101'
        assert args.config == 'config.ini'
    
    def test_mixed_arguments(self):
        """Test mixed boolean and string arguments."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args([
            '-v', '-s', '-q',
            '--tcp_ports_out', '80,443',
            '--udp_ports_out', '53,67',
            '--config', 'config.ini'
        ])
        assert args.verbose is True
        assert args.simulate is True
        assert args.quiet is True
        assert args.tcp_ports_out == '80,443'
        assert args.udp_ports_out == '53,67'
        assert args.config == 'config.ini'
    
    def test_empty_arguments(self):
        """Test empty arguments."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args([])
        assert args.verbose is False
        assert args.reset is False
        assert args.disallow_ping is False
        assert args.allow_outbound_icmp is False
        assert args.disallow_dhcp is False
        assert args.log_exceptions is False
        assert args.simulate is False
        assert args.quiet is False
        assert args.deny_all is False
        assert args.allow_all is False
        assert args.flush is False
        assert args.show_rules is False
        assert args.wizard is False
        assert args.windows_config is None
        assert args.tcp_ports_out is None
        assert args.udp_ports_out is None
        assert args.tcp_ports_in is None
        assert args.udp_ports_in is None
        assert args.outbound_hosts is None
        assert args.inbound_hosts is None
        assert args.exclude_hosts is None
        assert args.config is None


class TestBwCliEdgeCases:
    """Test BwCli edge cases."""
    
    def test_invalid_argument(self):
        """Test invalid argument."""
        cli = BwCli()
        parser = cli.parser
        
        with pytest.raises(SystemExit):
            parser.parse_args(['--invalid_argument'])
    
    def test_missing_value_for_string_argument(self):
        """Test missing value for string argument."""
        cli = BwCli()
        parser = cli.parser
        
        with pytest.raises(SystemExit):
            parser.parse_args(['--tcp_ports_out'])
    
    def test_duplicate_arguments(self):
        """Test duplicate arguments."""
        cli = BwCli()
        parser = cli.parser
        
        # This should work - last value wins
        args = parser.parse_args(['-v', '-v'])
        assert args.verbose is True
    
    def test_short_and_long_arguments(self):
        """Test short and long arguments together."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['-v', '--verbose'])
        assert args.verbose is True
    
    def test_argument_with_spaces(self):
        """Test argument with spaces."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--tcp_ports_out', '80, 443, 8080'])
        assert args.tcp_ports_out == '80, 443, 8080'
    
    def test_argument_with_special_characters(self):
        """Test argument with special characters."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--tcp_ports_out', '80,443,8080'])
        assert args.tcp_ports_out == '80,443,8080'
    
    def test_argument_with_empty_string(self):
        """Test argument with empty string."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args(['--tcp_ports_out', ''])
        assert args.tcp_ports_out == ''
    
    def test_argument_with_none_value(self):
        """Test argument with None value."""
        cli = BwCli()
        parser = cli.parser
        
        args = parser.parse_args([])
        assert args.tcp_ports_out is None
