#!/usr/bin/env python3
"""
Tests for firewall.utils.enumerate module.
"""

import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock, call
from firewall.utils.enumerate import pingSweep

# Patch root_check and parse_args for all tests
pytestmark = pytest.mark.usefixtures("mock_root_check", "mock_parse_args")


@pytest.fixture
def mock_root_check():
    """Mock root_check to avoid SystemExit."""
    with patch('firewall.utils.shell.Interact.root_check', return_value=True):
        yield


@pytest.fixture
def mock_parse_args():
    """Mock parse_args to avoid argparse errors."""
    with patch('firewall.base.cli_parser.BsCli.parse_args'):
        yield


class TestPingSweep:
    """Test pingSweep class."""
    
    def test_ping_sweep_initialization_default(self):
        """Test pingSweep initialization with default parameters."""
        ping_sweep = pingSweep()
        
        # When subnet=None, subnet attribute is not initialized
        assert not hasattr(ping_sweep, 'subnet')
        assert ping_sweep.threads == 4
        assert ping_sweep.alive == 0
        assert ping_sweep.alive_hosts == []
        assert ping_sweep.shuffle is False
        assert ping_sweep.verbose is False
    
    def test_ping_sweep_initialization_with_subnet(self):
        """Test pingSweep initialization with subnet."""
        ping_sweep = pingSweep(subnet='192.168.1.0/24')
        
        assert ping_sweep.subnet_raw == '192.168.1.0/24'
        assert len(ping_sweep.subnet) == 256  # 192.168.1.0/24 has 256 addresses
        assert ping_sweep.threads == 4
        assert ping_sweep.alive == 0
        assert ping_sweep.alive_hosts == []
    
    def test_ping_sweep_initialization_with_custom_params(self):
        """Test pingSweep initialization with custom parameters."""
        ping_sweep = pingSweep(
            subnet='10.0.0.0/8',
            threads=8,
            shuffle=True,
            verbose=True
        )
        
        assert ping_sweep.subnet_raw == '10.0.0.0/8'
        assert ping_sweep.threads == 8
        assert ping_sweep.shuffle is True
        assert ping_sweep.verbose is True
    
    def test_ping_sweep_initialization_invalid_subnet(self):
        """Test pingSweep initialization with invalid subnet."""
        with pytest.raises(Exception) as exc_info:
            ping_sweep(subnet='invalid_subnet')
        
        # The error message may vary, just check that an exception was raised
        assert exc_info.value is not None
    
    def test_ping_sweep_initialization_with_config(self):
        """Test pingSweep initialization with config."""
        config_content = """
[local_config]
target_range=192.168.1.0/24
trusted_range=192.168.1.0/24
nostrike=192.168.1.1
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            ping_sweep = pingSweep(subnet='192.168.1.0/24', config_in=config_path)
            
            assert ping_sweep.config_in == config_path
            assert ping_sweep.target_ranges is not None
            assert ping_sweep.trusted_range is not None
            assert ping_sweep.nostrike is not None
        finally:
            os.unlink(config_path)
    
    def test_ping_sweep_initialization_without_config(self):
        """Test pingSweep initialization without config."""
        ping_sweep = pingSweep(subnet='192.168.1.0/24', config_in=None)
        
        assert ping_sweep.config_in is None
        assert ping_sweep.nostrike is None
    
    def test_shuffle_host(self):
        """Test shuffle_host method."""
        ping_sweep = pingSweep(subnet='192.168.1.0/24')
        original_subnet = ping_sweep.subnet.copy()
        
        result = ping_sweep.shuffle_host()
        
        # Should return the same subnet (may be shuffled)
        assert result == ping_sweep.subnet
        # Should have the same length
        assert len(result) == len(original_subnet)
    
    @patch('subprocess.call')
    def test_pinger_success(self, mock_call):
        """Test pinger method with successful ping."""
        mock_call.return_value = 0
        
        ping_sweep = pingSweep(subnet='192.168.1.0/24')
        ping_sweep.nostrike = None
        
        # Mock the queue
        try:
            from Queue import Queue  # Python 2
        except ImportError:
            from queue import Queue  # Python 3
        queue = Queue()
        queue.put('192.168.1.1')
        
        # This will run in a loop, so we need to stop it
        with patch('time.sleep', side_effect=KeyboardInterrupt):
            try:
                ping_sweep.pinger(0, queue)
            except KeyboardInterrupt:
                pass
        
        # Check that subprocess.call was called
        mock_call.assert_called()
    
    @patch('subprocess.call')
    def test_pinger_failure(self, mock_call):
        """Test pinger method with failed ping."""
        mock_call.return_value = 1
        
        ping_sweep = pingSweep(subnet='192.168.1.0/24')
        ping_sweep.nostrike = None
        
        # Mock the queue
        try:
            from Queue import Queue  # Python 2
        except ImportError:
            from queue import Queue  # Python 3
        queue = Queue()
        queue.put('192.168.1.1')
        
        # This will run in a loop, so we need to stop it
        with patch('time.sleep', side_effect=KeyboardInterrupt):
            try:
                ping_sweep.pinger(0, queue)
            except KeyboardInterrupt:
                pass
        
        # Check that subprocess.call was called
        mock_call.assert_called()
    
    def test_pinger_with_nostrike(self):
        """Test pinger method with nostrike list."""
        ping_sweep = pingSweep(subnet='192.168.1.0/24')
        ping_sweep.nostrike = ['192.168.1.1']
        
        # Mock the queue
        try:
            from Queue import Queue  # Python 2
        except ImportError:
            from queue import Queue  # Python 3
        queue = Queue()
        queue.put('192.168.1.1')  # This IP is in nostrike
        
        # This will run in a loop, so we need to stop it
        with patch('time.sleep', side_effect=KeyboardInterrupt):
            try:
                ping_sweep.pinger(0, queue)
            except KeyboardInterrupt:
                pass
        
        # Should not ping IPs in nostrike list
        assert ping_sweep.alive == 0
    
    def test_thread_pool(self):
        """Test thread_pool method."""
        ping_sweep = pingSweep(subnet='192.168.1.0/24')
        
        with patch('firewall.utils.enumerate.Thread') as mock_thread:
            mock_worker = MagicMock()
            mock_thread.return_value = mock_worker
            
            ping_sweep.thread_pool()
            
            # Should create threads equal to self.threads
            assert mock_thread.call_count == ping_sweep.threads
            assert mock_worker.setDaemon.call_count == ping_sweep.threads
            assert mock_worker.start.call_count == ping_sweep.threads
    
    def test_queue_workers(self):
        """Test queue_workers method."""
        ping_sweep = pingSweep(subnet='192.168.1.0/24')
        
        # Mock the queue
        mock_queue = MagicMock()
        ping_sweep.queue = mock_queue
        
        ping_sweep.queue_workers()
        
        # Should put all IPs in the queue
        assert mock_queue.put.call_count == len(ping_sweep.subnet)
    
    @patch('subprocess.call')
    def test_get_alive_without_shuffle(self, mock_call):
        """Test get_alive method without shuffle."""
        mock_call.return_value = 0
        
        ping_sweep = pingSweep(subnet='192.168.1.0/24', shuffle=False)
        
        with patch.object(ping_sweep, 'thread_pool') as mock_thread_pool:
            with patch.object(ping_sweep, 'queue_workers') as mock_queue_workers:
                with patch.object(ping_sweep, 'queue') as mock_queue:
                    mock_queue.join.return_value = None
                    
                    result = ping_sweep.get_alive()
                    
                    mock_thread_pool.assert_called_once()
                    mock_queue_workers.assert_called_once()
                    mock_queue.join.assert_called_once()
                    assert result == ping_sweep.alive_hosts
    
    @patch('subprocess.call')
    def test_get_alive_with_shuffle(self, mock_call):
        """Test get_alive method with shuffle."""
        mock_call.return_value = 0
        
        ping_sweep = pingSweep(subnet='192.168.1.0/24', shuffle=True)
        
        with patch.object(ping_sweep, 'shuffle_host') as mock_shuffle:
            with patch.object(ping_sweep, 'thread_pool') as mock_thread_pool:
                with patch.object(ping_sweep, 'queue_workers') as mock_queue_workers:
                    with patch.object(ping_sweep, 'queue') as mock_queue:
                        mock_queue.join.return_value = None
                        
                        result = ping_sweep.get_alive()
                        
                        mock_shuffle.assert_called_once()
                        mock_thread_pool.assert_called_once()
                        mock_queue_workers.assert_called_once()
                        mock_queue.join.assert_called_once()
                        assert result == ping_sweep.alive_hosts
    
    def test_get_alive_verbose_with_alive_hosts(self):
        """Test get_alive method with verbose output when hosts are alive."""
        ping_sweep = pingSweep(subnet='192.168.1.0/24', verbose=True)
        ping_sweep.alive = 5
        
        with patch.object(ping_sweep, 'thread_pool') as mock_thread_pool:
            with patch.object(ping_sweep, 'queue_workers') as mock_queue_workers:
                with patch.object(ping_sweep, 'queue') as mock_queue:
                    mock_queue.join.return_value = None
                    
                    with patch('builtins.print') as mock_print:
                        result = ping_sweep.get_alive()
                        
                        # Should print verbose information
                        mock_print.assert_called()
    
    def test_get_alive_verbose_without_alive_hosts(self):
        """Test get_alive method with verbose output when no hosts are alive."""
        ping_sweep = pingSweep(subnet='192.168.1.0/24', verbose=True)
        ping_sweep.alive = 0
        
        with patch.object(ping_sweep, 'thread_pool') as mock_thread_pool:
            with patch.object(ping_sweep, 'queue_workers') as mock_queue_workers:
                with patch.object(ping_sweep, 'queue') as mock_queue:
                    mock_queue.join.return_value = None
                    
                    with patch('builtins.print') as mock_print:
                        result = ping_sweep.get_alive()
                        
                        # Should print verbose information
                        mock_print.assert_called()


class TestPingSweepEdgeCases:
    """Test pingSweep edge cases."""
    
    def test_ping_sweep_single_ip(self):
        """Test pingSweep with single IP address."""
        ping_sweep = pingSweep(subnet='192.168.1.1/32')
        
        assert ping_sweep.subnet_raw == '192.168.1.1/32'
        assert len(ping_sweep.subnet) == 1
        assert str(ping_sweep.subnet[0]) == '192.168.1.1'
    
    def test_ping_sweep_large_subnet(self):
        """Test pingSweep with large subnet."""
        # Use a smaller subnet to avoid performance issues
        ping_sweep = pingSweep(subnet='192.168.0.0/16')
        
        assert ping_sweep.subnet_raw == '192.168.0.0/16'
        assert len(ping_sweep.subnet) == 65536  # 192.168.0.0/16 has 65,536 addresses
    
    def test_ping_sweep_custom_threads(self):
        """Test pingSweep with custom thread count."""
        ping_sweep = pingSweep(subnet='192.168.1.0/24', threads=16)
        
        assert ping_sweep.threads == 16
    
    def test_ping_sweep_verbose_mode(self):
        """Test pingSweep with verbose mode."""
        ping_sweep = pingSweep(subnet='192.168.1.0/24', verbose=True)
        
        assert ping_sweep.verbose is True
    
    def test_ping_sweep_shuffle_mode(self):
        """Test pingSweep with shuffle mode."""
        ping_sweep = pingSweep(subnet='192.168.1.0/24', shuffle=True)
        
        assert ping_sweep.shuffle is True


class TestPingSweepIntegration:
    """Test pingSweep integration scenarios."""
    
    def test_ping_sweep_full_workflow(self):
        """Test complete pingSweep workflow."""
        ping_sweep = pingSweep(subnet='192.168.1.0/24', threads=2, verbose=True)
        
        with patch.object(ping_sweep, 'thread_pool') as mock_thread_pool:
            with patch.object(ping_sweep, 'queue_workers') as mock_queue_workers:
                with patch.object(ping_sweep, 'queue') as mock_queue:
                    mock_queue.join.return_value = None
                    
                    result = ping_sweep.get_alive()
                    
                    # Verify all methods were called
                    mock_thread_pool.assert_called_once()
                    mock_queue_workers.assert_called_once()
                    mock_queue.join.assert_called_once()
                    
                    # Verify return value
                    assert result == ping_sweep.alive_hosts
    
    def test_ping_sweep_with_config_workflow(self):
        """Test pingSweep workflow with configuration."""
        config_content = """
[local_config]
target_range=192.168.1.0/24
trusted_range=192.168.1.0/24
nostrike=192.168.1.1
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            ping_sweep = pingSweep(
                subnet='192.168.1.0/24',
                config_in=config_path,
                threads=4,
                verbose=True
            )
            
            with patch.object(ping_sweep, 'thread_pool') as mock_thread_pool:
                with patch.object(ping_sweep, 'queue_workers') as mock_queue_workers:
                    with patch.object(ping_sweep, 'queue') as mock_queue:
                        mock_queue.join.return_value = None
                        
                        result = ping_sweep.get_alive()
                        
                        # Verify configuration was loaded
                        assert ping_sweep.target_ranges is not None
                        assert ping_sweep.trusted_range is not None
                        assert ping_sweep.nostrike is not None
                        
                        # Verify workflow
                        mock_thread_pool.assert_called_once()
                        mock_queue_workers.assert_called_once()
                        mock_queue.join.assert_called_once()
                        assert result == ping_sweep.alive_hosts
        finally:
            os.unlink(config_path)
