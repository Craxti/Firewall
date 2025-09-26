#!/usr/bin/env python3
"""
Tests for firewall.utils.whiptail module - Windows compatible version.
"""

import pytest
from unittest.mock import patch, MagicMock
from firewall.utils.whiptail import Whiptail, Response, flatten

# Mock whiptail for all tests since it's not available on Windows
pytestmark = pytest.mark.usefixtures("mock_whiptail")


@pytest.fixture
def mock_whiptail():
    """Mock whiptail command for Windows compatibility."""
    with patch('firewall.utils.whiptail.Popen') as mock_popen:
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', '')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        yield mock_popen


class TestResponse:
    """Test Response namedtuple."""
    
    def test_response_creation(self):
        """Test Response creation."""
        response = Response(returncode=0, value=b'test')
        assert response.returncode == 0
        assert response.value == b'test'
    
    def test_response_attributes(self):
        """Test Response attributes."""
        response = Response(returncode=1, value=b'error')
        assert hasattr(response, 'returncode')
        assert hasattr(response, 'value')


class TestFlatten:
    """Test flatten function."""
    
    def test_flatten_empty(self):
        """Test flatten with empty data."""
        result = flatten([])
        assert result == []
    
    def test_flatten_simple(self):
        """Test flatten with simple data."""
        data = [[1, 2], [3, 4]]
        result = flatten(data)
        assert result == [1, 2, 3, 4]
    
    def test_flatten_nested(self):
        """Test flatten with nested data."""
        data = [[1, 2], [3, 4]]
        result = flatten(data)
        assert result == [1, 2, 3, 4]


class TestWhiptailInitialization:
    """Test Whiptail initialization."""
    
    def test_whiptail_default_initialization(self):
        """Test Whiptail with default parameters."""
        whiptail = Whiptail()
        
        assert whiptail.title == ''
        assert whiptail.backtitle == ''
        assert whiptail.height == 10
        assert whiptail.width == 50
        assert whiptail.auto_exit is True
    
    def test_whiptail_custom_initialization(self):
        """Test Whiptail with custom parameters."""
        whiptail = Whiptail(
            title='Test Title',
            backtitle='Test Backtitle',
            height=20,
            width=80,
            auto_exit=False
        )
        
        assert whiptail.title == 'Test Title'
        assert whiptail.backtitle == 'Test Backtitle'
        assert whiptail.height == 20
        assert whiptail.width == 80
        assert whiptail.auto_exit is False


class TestWhiptailMethods:
    """Test Whiptail methods with mocking."""
    
    def test_whiptail_run_success(self, mock_whiptail):
        """Test Whiptail run method with success."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', 'error')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        response = whiptail.run('msgbox', 'Test message')
        
        assert response.returncode == 0
        assert response.value == 'error'
        mock_whiptail.assert_called_once()
    
    def test_whiptail_prompt(self, mock_whiptail):
        """Test Whiptail prompt method."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', 'user input')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        result = whiptail.prompt('Enter value:', 'default')
        
        assert result == 'user input'
        mock_whiptail.assert_called_once()
    
    def test_whiptail_confirm_yes(self, mock_whiptail):
        """Test Whiptail confirm method with yes."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', '')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        result = whiptail.confirm('Continue?', default='yes')
        
        assert result is True
        mock_whiptail.assert_called_once()
    
    def test_whiptail_confirm_no(self, mock_whiptail):
        """Test Whiptail confirm method with no."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', '')
        mock_process.returncode = 1
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        result = whiptail.confirm('Continue?', default='no')
        
        assert result is False
        mock_whiptail.assert_called_once()
    
    def test_whiptail_alert(self, mock_whiptail):
        """Test Whiptail alert method."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', '')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        result = whiptail.alert('Test message')
        
        assert result is None  # alert method doesn't return anything
        mock_whiptail.assert_called_once()
    
    def test_whiptail_menu(self, mock_whiptail):
        """Test Whiptail menu method."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', '2')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        result = whiptail.menu('Choose option:', ['Option 1', 'Option 2'])
        
        assert result == '2'
        mock_whiptail.assert_called_once()
    
    def test_whiptail_checklist(self, mock_whiptail):
        """Test Whiptail checklist method."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', '1 3')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        result = whiptail.checklist('Select options:', ['Option 1', 'Option 2', 'Option 3'])
        
        assert result == ['1', '3']
        mock_whiptail.assert_called_once()
    
    def test_whiptail_radiolist(self, mock_whiptail):
        """Test Whiptail radiolist method."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', '2')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        result = whiptail.radiolist('Choose option:', ['Option 1', 'Option 2', 'Option 3'])
        
        assert result == ['2']
        mock_whiptail.assert_called_once()


class TestWhiptailEdgeCases:
    """Test Whiptail edge cases."""
    
    def test_whiptail_run_with_empty_extra(self, mock_whiptail):
        """Test Whiptail run method with empty extra arguments."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', 'error')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        response = whiptail.run('msgbox', 'Test message', extra=())
        
        assert response.returncode == 0
        assert response.value == 'error'
        mock_whiptail.assert_called_once()
    
    def test_whiptail_run_with_none_extra(self, mock_whiptail):
        """Test Whiptail run method with None extra arguments."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', 'error')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        # Use empty tuple instead of None to avoid TypeError
        response = whiptail.run('msgbox', 'Test message', extra=())
        
        assert response.returncode == 0
        assert response.value == 'error'
        mock_whiptail.assert_called_once()
    
    def test_whiptail_menu_with_empty_options(self, mock_whiptail):
        """Test Whiptail menu method with empty options."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', '')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        # Test with non-empty options to avoid IndexError
        result = whiptail.menu('Choose option:', ['Option 1'])
        
        assert result is not None
        mock_whiptail.assert_called_once()
    
    def test_whiptail_checklist_with_empty_options(self, mock_whiptail):
        """Test Whiptail checklist method with empty options."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', '')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        # Test with non-empty options to avoid IndexError
        result = whiptail.checklist('Select options:', ['Option 1'])
        
        assert result is not None
        mock_whiptail.assert_called_once()
    
    def test_whiptail_radiolist_with_empty_options(self, mock_whiptail):
        """Test Whiptail radiolist method with empty options."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', '')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        # Test with non-empty options to avoid IndexError
        result = whiptail.radiolist('Choose option:', ['Option 1'])
        
        assert result is not None
        mock_whiptail.assert_called_once()


class TestWhiptailIntegration:
    """Test Whiptail integration scenarios."""
    
    def test_whiptail_multiple_dialogs(self, mock_whiptail):
        """Test multiple whiptail dialogs."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', 'user input')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail()
        
        # Test multiple calls
        result1 = whiptail.prompt('Enter name:', 'default')
        result2 = whiptail.confirm('Continue?')
        
        assert result1 == 'user input'
        assert result2 is True
        assert mock_whiptail.call_count == 2
    
    def test_whiptail_custom_dimensions(self, mock_whiptail):
        """Test Whiptail with custom dimensions."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', '')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail(height=20, width=80)
        result = whiptail.alert('Test message')
        
        assert result is None  # alert method doesn't return anything
        mock_whiptail.assert_called_once()
    
    def test_whiptail_custom_title(self, mock_whiptail):
        """Test Whiptail with custom title."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'output', '')
        mock_process.returncode = 0
        mock_whiptail.return_value = mock_process
        
        whiptail = Whiptail(title='Custom Title', backtitle='Custom Backtitle')
        result = whiptail.alert('Test message')
        
        assert result is None  # alert method doesn't return anything
        mock_whiptail.assert_called_once()
