#!/usr/bin/env python3
"""
Tests for firewall.utils.superset module.
"""

import pytest
import os
import tempfile
import json
from unittest.mock import patch, mock_open
from firewall.utils.superset import AOR


class TestAOR:
    """Test AOR class."""
    
    def test_aor_initialization_without_config(self):
        """Test AOR initialization without config."""
        with pytest.raises(Exception) as exc_info:
            AOR()
        assert "Cannot continue without config!" in str(exc_info.value)
    
    def test_aor_initialization_with_config(self):
        """Test AOR initialization with config."""
        config_content = """
[local_config]
iface=eth0
rh_host=test-host
rh_ipaddr=192.168.1.1

[firewall_config]
target_range=192.168.1.0/24
trusted_range=192.168.2.0/24
nostrike=192.168.1.100
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR(config=config_path, DEBUG=False, VERBOSE=False)
            assert aor.configs is not None
            assert 'target_range' in aor.configs
            assert 'trusted_range' in aor.configs
            assert 'nostrike' in aor.configs
        finally:
            os.unlink(config_path)
    
    def test_aor_initialization_with_debug(self):
        """Test AOR initialization with debug mode."""
        config_content = """
[local_config]
iface=eth0
rh_host=test-host
rh_ipaddr=192.168.1.1
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            with patch('builtins.print') as mock_print:
                aor = AOR(config=config_path, DEBUG=True, VERBOSE=False)
                assert aor.debug is True
                assert aor.verbose is False
        finally:
            os.unlink(config_path)
    
    def test_aor_initialization_with_verbose(self):
        """Test AOR initialization with verbose mode."""
        config_content = """
[local_config]
iface=eth0
rh_host=test-host
rh_ipaddr=192.168.1.1
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR(config=config_path, DEBUG=False, VERBOSE=True)
            assert aor.debug is False
            assert aor.verbose is True
        finally:
            os.unlink(config_path)


class TestAORConfigParsing:
    """Test AOR config parsing functionality."""
    
    def test_get_config_from_file_nonexistent(self):
        """Test config parsing with nonexistent file."""
        with patch('builtins.print') as mock_print:
            aor = AOR.__new__(AOR)
            aor.verbose = True
            aor.debug = False
            result = aor.get_config_from_file("nonexistent.ini")
            assert result is None
            mock_print.assert_called_with("getting config from wizard")
    
    def test_get_config_from_file_existent(self):
        """Test config parsing with existent file."""
        config_content = """
[local_config]
iface=eth0
rh_host=test-host
rh_ipaddr=192.168.1.1

[firewall_config]
target_range=192.168.1.0/24
trusted_range=192.168.2.0/24
nostrike=192.168.1.100
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'target_range' in result
            assert 'trusted_range' in result
            assert 'nostrike' in result
            assert '192.168.1.0/24' in result['target_range']
            assert '192.168.2.0/24' in result['trusted_range']
            assert '192.168.1.100' in result['nostrike']
        finally:
            os.unlink(config_path)
    
    def test_get_config_from_file_with_comments(self):
        """Test config parsing with comments."""
        config_content = """
# This is a comment
[local_config]
iface=eth0
# Another comment
rh_host=test-host
rh_ipaddr=192.168.1.1
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'iface' in result
            assert result['iface'] == ['eth0']
        finally:
            os.unlink(config_path)
    
    def test_get_config_from_file_with_invalid_lines(self):
        """Test config parsing with invalid lines."""
        config_content = """
[local_config]
iface=eth0
invalid_line_without_equals
rh_host=test-host
rh_ipaddr=192.168.1.1
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'iface' in result
            assert result['iface'] == ['eth0']
        finally:
            os.unlink(config_path)
    
    def test_get_config_from_file_with_debug(self):
        """Test config parsing with debug mode."""
        config_content = """
[local_config]
iface=eth0
rh_host=test-host
rh_ipaddr=192.168.1.1
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            with patch('builtins.print') as mock_print:
                aor = AOR.__new__(AOR)
                aor.verbose = False
                aor.debug = True
                result = aor.get_config_from_file(config_path)
                
                assert result is not None
                mock_print.assert_called()
        finally:
            os.unlink(config_path)


class TestAORConfigTypes:
    """Test AOR config type handling."""
    
    def test_get_config_from_file_target_range(self):
        """Test config parsing with target_range."""
        config_content = """
[firewall_config]
target_range=192.168.1.0/24
target_range=192.168.2.0/24
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'target_range' in result
            assert len(result['target_range']) == 2
            assert '192.168.1.0/24' in result['target_range']
            assert '192.168.2.0/24' in result['target_range']
        finally:
            os.unlink(config_path)
    
    def test_get_config_from_file_trusted_range(self):
        """Test config parsing with trusted_range."""
        config_content = """
[firewall_config]
trusted_range=192.168.1.0/24
trusted_range=192.168.2.0/24
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'trusted_range' in result
            assert len(result['trusted_range']) == 2
            assert '192.168.1.0/24' in result['trusted_range']
            assert '192.168.2.0/24' in result['trusted_range']
        finally:
            os.unlink(config_path)
    
    def test_get_config_from_file_trusted_host(self):
        """Test config parsing with trusted_host."""
        config_content = """
[firewall_config]
trusted_host=192.168.1.1
trusted_host=192.168.1.2
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'trusted_host' in result
            assert len(result['trusted_host']) == 2
            assert '192.168.1.1' in result['trusted_host']
            assert '192.168.1.2' in result['trusted_host']
        finally:
            os.unlink(config_path)
    
    def test_get_config_from_file_target_host(self):
        """Test config parsing with target_host."""
        config_content = """
[firewall_config]
target_host=192.168.1.1
target_host=192.168.1.2
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'target_host' in result
            assert len(result['target_host']) == 2
            assert '192.168.1.1' in result['target_host']
            assert '192.168.1.2' in result['target_host']
        finally:
            os.unlink(config_path)
    
    def test_get_config_from_file_nostrike(self):
        """Test config parsing with nostrike."""
        config_content = """
[firewall_config]
nostrike=192.168.1.100
nostrike=192.168.1.101
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'nostrike' in result
            assert len(result['nostrike']) == 2
            assert '192.168.1.100' in result['nostrike']
            assert '192.168.1.101' in result['nostrike']
        finally:
            os.unlink(config_path)


class TestAORConfigComplex:
    """Test AOR complex config scenarios."""
    
    def test_get_config_from_file_complete_config(self):
        """Test config parsing with complete configuration."""
        config_content = """
[local_config]
iface=eth0
rh_host=test-host
rh_ipaddr=192.168.1.1
netmask=255.255.255.0
gateway_addr=192.168.1.1
dns=8.8.8.8

[firewall_config]
target_range=192.168.1.0/24
target_range=192.168.2.0/24
trusted_range=192.168.3.0/24
trusted_host=192.168.1.100
target_host=192.168.1.200
nostrike=192.168.1.50
nostrike=192.168.1.51
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'iface' in result
            assert result['iface'] == ['eth0']
            assert 'rh_host' in result
            assert result['rh_host'] == ['test-host']
            assert 'rh_ipaddr' in result
            assert result['rh_ipaddr'] == ['192.168.1.1']
            assert 'netmask' in result
            assert result['netmask'] == ['255.255.255.0']
            assert 'gateway_addr' in result
            assert result['gateway_addr'] == ['192.168.1.1']
            assert 'dns' in result
            assert result['dns'] == ['8.8.8.8']
            
            assert 'target_range' in result
            assert len(result['target_range']) == 2
            assert '192.168.1.0/24' in result['target_range']
            assert '192.168.2.0/24' in result['target_range']
            
            assert 'trusted_range' in result
            assert len(result['trusted_range']) == 1
            assert '192.168.3.0/24' in result['trusted_range']
            
            assert 'trusted_host' in result
            assert len(result['trusted_host']) == 1
            assert '192.168.1.100' in result['trusted_host']
            
            assert 'target_host' in result
            assert len(result['target_host']) == 1
            assert '192.168.1.200' in result['target_host']
            
            assert 'nostrike' in result
            assert len(result['nostrike']) == 2
            assert '192.168.1.50' in result['nostrike']
            assert '192.168.1.51' in result['nostrike']
        finally:
            os.unlink(config_path)
    
    def test_get_config_from_file_empty_file(self):
        """Test config parsing with empty file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write("")
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'target_range' in result
            assert 'trusted_range' in result
            assert 'trusted_host' in result
            assert 'target_host' in result
            assert 'nostrike' in result
            assert len(result['target_range']) == 0
            assert len(result['trusted_range']) == 0
            assert len(result['trusted_host']) == 0
            assert len(result['target_host']) == 0
            assert len(result['nostrike']) == 0
        finally:
            os.unlink(config_path)
    
    def test_get_config_from_file_whitespace_handling(self):
        """Test config parsing with whitespace handling."""
        config_content = """
[local_config]
iface = eth0
rh_host = test-host
rh_ipaddr = 192.168.1.1
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'iface ' in result
            assert result['iface '] == [' eth0']
            assert 'rh_host ' in result
            assert result['rh_host '] == [' test-host']
            assert 'rh_ipaddr ' in result
            assert result['rh_ipaddr '] == [' 192.168.1.1']
        finally:
            os.unlink(config_path)


class TestAORJSONOutput:
    """Test AOR JSON output functionality."""
    
    def test_get_config_from_file_with_json_output(self):
        """Test config parsing with JSON output."""
        config_content = """
[local_config]
iface=eth0
rh_host=test-host
rh_ipaddr=192.168.1.1
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path, write_json=True, json_out='test_config.json')
            
            assert result is not None
            assert os.path.exists('test_config.json')
            
            # Clean up
            if os.path.exists('test_config.json'):
                os.unlink('test_config.json')
        finally:
            os.unlink(config_path)
    
    def test_get_config_from_file_json_output_content(self):
        """Test config parsing JSON output content."""
        config_content = """
[local_config]
iface=eth0
rh_host=test-host
rh_ipaddr=192.168.1.1
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path, write_json=True, json_out='test_config.json')
            
            assert result is not None
            assert os.path.exists('test_config.json')
            
            # Read and verify JSON content
            with open('test_config.json', 'r') as f:
                json_data = json.load(f)
                assert 'iface' in json_data
                assert json_data['iface'] == ['eth0']
                assert 'rh_host' in json_data
                assert json_data['rh_host'] == ['test-host']
                assert 'rh_ipaddr' in json_data
                assert json_data['rh_ipaddr'] == ['192.168.1.1']
            
            # Clean up
            if os.path.exists('test_config.json'):
                os.unlink('test_config.json')
        finally:
            os.unlink(config_path)


class TestAOREdgeCases:
    """Test AOR edge cases."""
    
    def test_get_config_from_file_case_insensitive(self):
        """Test config parsing with case insensitive keys."""
        config_content = """
[local_config]
IFACE=eth0
RH_HOST=test-host
RH_IPADDR=192.168.1.1
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'iface' in result
            assert result['iface'] == ['eth0']
            assert 'rh_host' in result
            assert result['rh_host'] == ['test-host']
            assert 'rh_ipaddr' in result
            assert result['rh_ipaddr'] == ['192.168.1.1']
        finally:
            os.unlink(config_path)
    
    def test_get_config_from_file_duplicate_keys(self):
        """Test config parsing with duplicate keys."""
        config_content = """
[local_config]
iface=eth0
iface=eth1
rh_host=test-host
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'iface' in result
            # Should keep the last value
            assert result['iface'] == ['eth0', 'eth1']
        finally:
            os.unlink(config_path)
    
    def test_get_config_from_file_special_characters(self):
        """Test config parsing with special characters."""
        config_content = """
[local_config]
iface=eth0
rh_host=test-host-with-dashes
rh_ipaddr=192.168.1.1
description=Test with spaces and special chars!@#$%^&*()
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            aor = AOR.__new__(AOR)
            aor.verbose = False
            aor.debug = False
            result = aor.get_config_from_file(config_path)
            
            assert result is not None
            assert 'iface' in result
            assert result['iface'] == ['eth0']
            assert 'rh_host' in result
            assert result['rh_host'] == ['test-host-with-dashes']
            assert 'rh_ipaddr' in result
            assert result['rh_ipaddr'] == ['192.168.1.1']
            assert 'description' in result
            assert result['description'] == ['Test with spaces and special chars!@#$%^&*()']
        finally:
            os.unlink(config_path)
