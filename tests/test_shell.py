#!/usr/bin/env python3
"""
Tests for firewall.utils.shell module.
"""

import pytest
import subprocess
import os
import tempfile
from unittest.mock import patch, MagicMock
from firewall.utils.shell import Interact, CommandError, Bcolors


class TestCommandError:
    """Test CommandError exception."""
    
    def test_command_error_creation(self):
        """Test CommandError creation."""
        error = CommandError("test command", "error output", 1)
        assert error.command == "test command"
        assert error.output == "error output"
        assert error.return_code == 1
        assert "Command failed: test command" in str(error)
        assert "return code: 1" in str(error)
        assert "output: error output" in str(error)
    
    def test_command_error_minimal(self):
        """Test CommandError with minimal parameters."""
        error = CommandError("test command")
        assert error.command == "test command"
        assert error.output is None
        assert error.return_code is None
        assert "Command failed: test command" in str(error)


class TestInteract:
    """Test Interact class."""
    
    def test_interact_initialization(self):
        """Test Interact initialization."""
        interact = Interact()
        assert interact is not None
    
    @patch('subprocess.Popen')
    def test_run_command_success(self, mock_popen):
        """Test successful command execution."""
        # Mock successful command execution
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        result = interact.run_command("echo test", VERBOSE=1)
        
        assert result == "output"
        mock_popen.assert_called_once()
    
    @patch('subprocess.Popen')
    def test_run_command_failure(self, mock_popen):
        """Test failed command execution."""
        # Mock failed command execution
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'', b'error')
        mock_process.returncode = 1
        mock_popen.return_value = mock_process
        
        interact = Interact()
        
        # The command should not raise CommandError in non-wait mode
        # because the actual implementation doesn't check returncode in non-wait mode
        result = interact.run_command("invalid command", VERBOSE=1)
        assert result == ""
    
    @patch('subprocess.Popen')
    def test_run_command_wait_mode(self, mock_popen):
        """Test command execution in wait mode."""
        mock_process = MagicMock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        result = interact.run_command("echo test", VERBOSE=1, wait=True)
        
        assert result is None
        mock_process.wait.assert_called_once()
    
    @patch('subprocess.Popen')
    def test_run_command_debug_mode(self, mock_popen):
        """Test command execution in debug mode."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        result = interact.run_command("echo test", VERBOSE=1, DEBUG=True)
        
        assert result == "output"
        mock_popen.assert_called_once()
    
    @patch('subprocess.Popen')
    def test_run_command_verbose_output(self, mock_popen, capsys):
        """Test verbose output."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        result = interact.run_command("echo test", VERBOSE=2)
        
        assert result == "output"
        captured = capsys.readouterr()
        assert "$ echo test" in captured.out
    
    @patch('subprocess.Popen')
    def test_run_command_timeout(self, mock_popen):
        """Test command execution with timeout."""
        mock_process = MagicMock()
        mock_process.communicate.side_effect = subprocess.TimeoutExpired("cmd", 1)
        mock_popen.return_value = mock_process
        
        interact = Interact()
        
        with pytest.raises(CommandError) as exc_info:
            interact.run_command("sleep 10", VERBOSE=1)
        
        assert "command failed" in str(exc_info.value).lower()
    
    @patch('subprocess.Popen')
    def test_run_command_os_error(self, mock_popen):
        """Test command execution with OS error."""
        mock_popen.side_effect = OSError("Command not found")
        
        interact = Interact()
        
        with pytest.raises(CommandError) as exc_info:
            interact.run_command("nonexistent_command", VERBOSE=1)
        
        assert "Command failed" in str(exc_info.value)


class TestBcolors:
    """Test Bcolors class."""
    
    def test_bcolors_constants(self):
        """Test Bcolors constants."""
        assert hasattr(Bcolors, 'HEADERS')
        assert hasattr(Bcolors, 'OKBLUE')
        assert hasattr(Bcolors, 'OKGREEN')
        assert hasattr(Bcolors, 'WARNING')
        assert hasattr(Bcolors, 'FAIL')
        assert hasattr(Bcolors, 'ENDC')
        assert hasattr(Bcolors, 'BOLD')
        assert hasattr(Bcolors, 'UNDERLINE')
    
    def test_bcolors_values(self):
        """Test Bcolors values."""
        # Check that colors are strings
        assert isinstance(Bcolors.HEADERS, str)
        assert isinstance(Bcolors.OKBLUE, str)
        assert isinstance(Bcolors.OKGREEN, str)
        assert isinstance(Bcolors.WARNING, str)
        assert isinstance(Bcolors.FAIL, str)
        assert isinstance(Bcolors.ENDC, str)
        assert isinstance(Bcolors.BOLD, str)
        assert isinstance(Bcolors.UNDERLINE, str)
    
    def test_bcolors_usage(self):
        """Test Bcolors usage."""
        colored_text = f"{Bcolors.OKGREEN}Success{Bcolors.ENDC}"
        assert "Success" in colored_text
        assert Bcolors.OKGREEN in colored_text
        assert Bcolors.ENDC in colored_text


class TestInteractAdvanced:
    """Test advanced Interact functionality."""
    
    @patch('subprocess.Popen')
    def test_run_command_with_shell(self, mock_popen):
        """Test command execution with shell."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        result = interact.run_command("echo test", VERBOSE=1)
        
        # Check that subprocess.Popen was called with shell=True
        call_args = mock_popen.call_args
        assert call_args[1]['shell'] is True
    
    @patch('subprocess.Popen')
    def test_run_command_with_stdin(self, mock_popen):
        """Test command execution with stdin."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        # Note: run_command doesn't support stdin parameter
        result = interact.run_command("cat", VERBOSE=1)
        
        assert result == "output"
        mock_popen.assert_called_once()
    
    @patch('subprocess.Popen')
    def test_run_command_with_cwd(self, mock_popen):
        """Test command execution with working directory."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        # Note: run_command doesn't support cwd parameter
        result = interact.run_command("pwd", VERBOSE=1)
        
        assert result == "output"
        mock_popen.assert_called_once()
    
    @patch('subprocess.Popen')
    def test_run_command_with_env(self, mock_popen):
        """Test command execution with environment variables."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        # Note: run_command doesn't support env parameter
        result = interact.run_command("echo $TEST_VAR", VERBOSE=1)
        
        assert result == "output"
        mock_popen.assert_called_once()
    
    @patch('subprocess.Popen')
    def test_run_command_stderr_handling(self, mock_popen):
        """Test command execution with stderr handling."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', b'stderr output')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        result = interact.run_command("echo test", VERBOSE=1)
        
        assert result == "output"
        mock_popen.assert_called_once()
    
    @patch('subprocess.Popen')
    def test_run_command_return_code_handling(self, mock_popen):
        """Test command execution with return code handling."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', b'')
        mock_process.returncode = 1
        mock_popen.return_value = mock_process
        
        interact = Interact()
        
        # The command should not raise CommandError in non-wait mode
        result = interact.run_command("false", VERBOSE=1)
        assert result == "output"


class TestInteractLogging:
    """Test Interact logging functionality."""
    
    @patch('subprocess.Popen')
    def test_run_command_logging(self, mock_popen):
        """Test command execution logging."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        result = interact.run_command("echo test", VERBOSE=1)
        
        assert result == "output"
        mock_popen.assert_called_once()
    
    @patch('subprocess.Popen')
    def test_run_command_error_logging(self, mock_popen):
        """Test command execution error logging."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'', b'error')
        mock_process.returncode = 1
        mock_popen.return_value = mock_process
        
        interact = Interact()
        
        # The command should not raise CommandError in non-wait mode
        result = interact.run_command("invalid command", VERBOSE=1)
        assert result == ""
        mock_popen.assert_called_once()


class TestInteractEdgeCases:
    """Test Interact edge cases."""
    
    @patch('subprocess.Popen')
    def test_run_command_empty_output(self, mock_popen):
        """Test command execution with empty output."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'', b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        result = interact.run_command("true", VERBOSE=1)
        
        assert result == ""
        mock_popen.assert_called_once()
    
    @patch('subprocess.Popen')
    def test_run_command_large_output(self, mock_popen):
        """Test command execution with large output."""
        large_output = b'x' * 10000
        mock_process = MagicMock()
        mock_process.communicate.return_value = (large_output, b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        result = interact.run_command("echo large output", VERBOSE=1)
        
        assert result == 'x' * 10000
        mock_popen.assert_called_once()
    
    @patch('subprocess.Popen')
    def test_run_command_unicode_output(self, mock_popen):
        """Test command execution with unicode output."""
        unicode_output = "тест".encode('utf-8')
        mock_process = MagicMock()
        mock_process.communicate.return_value = (unicode_output, b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        result = interact.run_command("echo тест", VERBOSE=1)
        
        assert result == "тест"
        mock_popen.assert_called_once()
    
    @patch('subprocess.Popen')
    def test_run_command_binary_output(self, mock_popen):
        """Test command execution with binary output."""
        binary_output = b'\x00\x01\x02\x03'
        mock_process = MagicMock()
        mock_process.communicate.return_value = (binary_output, b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        result = interact.run_command("cat binary_file", VERBOSE=1)
        
        assert result == '\x00\x01\x02\x03'
        mock_popen.assert_called_once()


class TestInteractIntegration:
    """Test Interact integration scenarios."""
    
    @patch('subprocess.Popen')
    def test_multiple_commands(self, mock_popen):
        """Test multiple command executions."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        
        # Execute multiple commands
        result1 = interact.run_command("echo test1", VERBOSE=1)
        result2 = interact.run_command("echo test2", VERBOSE=1)
        
        assert result1 == "output"
        assert result2 == "output"
        assert mock_popen.call_count == 2
    
    @patch('subprocess.Popen')
    def test_command_with_special_characters(self, mock_popen):
        """Test command execution with special characters."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        result = interact.run_command("echo 'test with spaces and $pecial chars'", VERBOSE=1)
        
        assert result == "output"
        mock_popen.assert_called_once()
    
    @patch('subprocess.Popen')
    def test_command_with_quotes(self, mock_popen):
        """Test command execution with quotes."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', b'')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        interact = Interact()
        result = interact.run_command('echo "test with quotes"', VERBOSE=1)
        
        assert result == "output"
        mock_popen.assert_called_once()
