#!/usr/bin/env python3
"""
Tests for firewall.utils.ipaddr module.
"""

import pytest
import ipaddress
from firewall.utils.ipaddr import IPv4Address, IPv6Address, IPv4Network, IPv6Network


class TestIPv4Address:
    """Test IPv4Address functionality."""
    
    def test_ipv4_address_creation(self):
        """Test IPv4 address creation."""
        addr = IPv4Address('192.168.1.1')
        assert str(addr) == '192.168.1.1'
        assert addr.version == 4
    
    def test_ipv4_address_invalid(self):
        """Test invalid IPv4 address."""
        with pytest.raises(ValueError):
            IPv4Address('256.256.256.256')
    
    def test_ipv4_address_comparison(self):
        """Test IPv4 address comparison."""
        addr1 = IPv4Address('192.168.1.1')
        addr2 = IPv4Address('192.168.1.2')
        addr3 = IPv4Address('192.168.1.1')
        
        assert addr1 < addr2
        assert addr1 == addr3
        assert addr1 != addr2
    
    def test_ipv4_address_arithmetic(self):
        """Test IPv4 address arithmetic."""
        addr = IPv4Address('192.168.1.1')
        next_addr = addr + 1
        assert str(next_addr) == '192.168.1.2'
        
        prev_addr = addr - 1
        assert str(prev_addr) == '192.168.1.0'


class TestIPv6Address:
    """Test IPv6Address functionality."""
    
    def test_ipv6_address_creation(self):
        """Test IPv6 address creation."""
        addr = IPv6Address('2001:db8::1')
        assert str(addr) == '2001:db8::1'
        assert addr.version == 6
    
    def test_ipv6_address_invalid(self):
        """Test invalid IPv6 address."""
        with pytest.raises(ValueError):
            IPv6Address('gggg::1')
    
    def test_ipv6_address_comparison(self):
        """Test IPv6 address comparison."""
        addr1 = IPv6Address('2001:db8::1')
        addr2 = IPv6Address('2001:db8::2')
        addr3 = IPv6Address('2001:db8::1')
        
        assert addr1 < addr2
        assert addr1 == addr3
        assert addr1 != addr2


class TestIPv4Network:
    """Test IPv4Network functionality."""
    
    def test_ipv4_network_creation(self):
        """Test IPv4 network creation."""
        network = IPv4Network('192.168.1.0/24')
        assert str(network.network) == '192.168.1.0'
        assert network.prefixlen == 24
        assert network.numhosts == 256
    
    def test_ipv4_network_hosts(self):
        """Test IPv4 network hosts."""
        network = IPv4Network('192.168.1.0/30')
        hosts = list(network)
        assert len(hosts) == 4
        assert str(hosts[0]) == '192.168.1.0'
        assert str(hosts[1]) == '192.168.1.1'
    
    def test_ipv4_network_contains(self):
        """Test IPv4 network contains."""
        network = IPv4Network('192.168.1.0/24')
        assert IPv4Address('192.168.1.1') in network
        assert IPv4Address('192.168.2.1') not in network
    
    def test_ipv4_network_subnets(self):
        """Test IPv4 network subnets."""
        network = IPv4Network('192.168.1.0/24')
        subnets = list(network.iter_subnets(prefixlen_diff=1))
        assert len(subnets) == 2
        assert str(subnets[0]) == '192.168.1.0/25'
        assert str(subnets[1]) == '192.168.1.128/25'


class TestIPv6Network:
    """Test IPv6Network functionality."""
    
    def test_ipv6_network_creation(self):
        """Test IPv6 network creation."""
        network = IPv6Network('2001:db8::/32')
        assert str(network.network) == '2001:db8::'
        assert network.prefixlen == 32
    
    def test_ipv6_network_contains(self):
        """Test IPv6 network contains."""
        network = IPv6Network('2001:db8::/32')
        assert IPv6Address('2001:db8::1') in network
        assert IPv6Address('2001:db9::1') not in network


class TestNetworkUtilities:
    """Test network utility functions."""
    
    def test_network_overlaps(self):
        """Test network overlap detection."""
        net1 = IPv4Network('192.168.1.0/24')
        net2 = IPv4Network('192.168.1.128/25')
        net3 = IPv4Network('192.168.2.0/24')
        
        assert net1.overlaps(net2)
        assert not net1.overlaps(net3)
    
    def test_network_supernet(self):
        """Test network supernet."""
        network = IPv4Network('192.168.1.0/25')
        supernet = network.supernet(prefixlen_diff=1)
        assert str(supernet) == '192.168.1.0/24'
    
    def test_network_addresses(self):
        """Test network address iteration."""
        network = IPv4Network('192.168.1.0/30')
        addresses = list(network)
        assert len(addresses) == 4
        assert str(addresses[0]) == '192.168.1.0'
        assert str(addresses[-1]) == '192.168.1.3'


class TestIPAddressValidation:
    """Test IP address validation functions."""
    
    def test_is_valid_ipv4(self):
        """Test IPv4 validation."""
        assert IPv4Address('192.168.1.1').is_private
        assert not IPv4Address('8.8.8.8').is_private
        assert IPv4Address('127.0.0.1').is_loopback
        assert IPv4Address('169.254.1.1').is_link_local
    
    def test_is_valid_ipv6(self):
        """Test IPv6 validation."""
        assert IPv6Address('::1').is_loopback
        assert IPv6Address('fe80::1').is_link_local
        assert not IPv6Address('2001:db8::1').is_private
    
    def test_address_compression(self):
        """Test address compression."""
        addr = IPv6Address('2001:0db8:0000:0000:0000:0000:0000:0001')
        assert str(addr) == '2001:db8::1'
    
    def test_address_expansion(self):
        """Test address expansion."""
        addr = IPv6Address('2001:db8::1')
        expanded = addr.exploded
        assert '2001:0db8:0000:0000:0000:0000:0000:0001' in expanded


class TestNetworkOperations:
    """Test network operations."""
    
    def test_network_intersection(self):
        """Test network intersection."""
        net1 = IPv4Network('192.168.1.0/24')
        net2 = IPv4Network('192.168.1.128/25')
        intersection = net1.intersection(net2)
        assert str(intersection) == '192.168.1.128/25'
    
    def test_network_union(self):
        """Test network union."""
        net1 = IPv4Network('192.168.1.0/25')
        net2 = IPv4Network('192.168.1.128/25')
        union = net1.union(net2)
        assert str(union) == '192.168.1.0/24'
    
    def test_network_difference(self):
        """Test network difference."""
        net1 = IPv4Network('192.168.1.0/24')
        net2 = IPv4Network('192.168.1.128/25')
        difference = net1.difference(net2)
        assert str(difference) == '192.168.1.0/25'


class TestAddressConversion:
    """Test address conversion functions."""
    
    def test_ipv4_to_int(self):
        """Test IPv4 to integer conversion."""
        addr = IPv4Address('192.168.1.1')
        assert addr._ip == 3232235777
    
    def test_int_to_ipv4(self):
        """Test integer to IPv4 conversion."""
        addr = IPv4Address(3232235777)
        assert str(addr) == '192.168.1.1'
    
    def test_ipv6_to_int(self):
        """Test IPv6 to integer conversion."""
        addr = IPv6Address('::1')
        assert addr._ip == 1
    
    def test_int_to_ipv6(self):
        """Test integer to IPv6 conversion."""
        addr = IPv6Address(1)
        assert str(addr) == '::1'


class TestNetworkProperties:
    """Test network properties."""
    
    def test_network_broadcast(self):
        """Test network broadcast address."""
        network = IPv4Network('192.168.1.0/24')
        assert str(network.broadcast) == '192.168.1.255'
    
    def test_network_netmask(self):
        """Test network netmask."""
        network = IPv4Network('192.168.1.0/24')
        assert str(network.netmask) == '255.255.255.0'
    
    def test_network_hostmask(self):
        """Test network hostmask."""
        network = IPv4Network('192.168.1.0/24')
        assert str(network.hostmask) == '0.0.0.255'
    
    def test_network_with_prefixlen(self):
        """Test network with prefix length."""
        network = IPv4Network('192.168.1.0/24')
        assert network.with_prefixlen == '192.168.1.0/24'
        assert network.with_netmask == '192.168.1.0/255.255.255.0'
        assert network.with_hostmask == '192.168.1.0/0.0.0.255'


class TestNetworkIteration:
    """Test network iteration."""
    
    def test_network_iteration(self):
        """Test network iteration."""
        network = IPv4Network('192.168.1.0/30')
        addresses = list(network)
        assert len(addresses) == 4
        assert str(addresses[0]) == '192.168.1.0'
        assert str(addresses[-1]) == '192.168.1.3'
    
    def test_network_hosts_iteration(self):
        """Test network hosts iteration."""
        network = IPv4Network('192.168.1.0/30')
        hosts = list(network)
        assert len(hosts) == 4
        assert str(hosts[0]) == '192.168.1.0'
        assert str(hosts[1]) == '192.168.1.1'
    
    def test_network_subnets_iteration(self):
        """Test network subnets iteration."""
        network = IPv4Network('192.168.1.0/24')
        subnets = list(network.iter_subnets(prefixlen_diff=1))
        assert len(subnets) == 2
        assert str(subnets[0]) == '192.168.1.0/25'
        assert str(subnets[1]) == '192.168.1.128/25'


class TestAddressProperties:
    """Test address properties."""
    
    def test_ipv4_properties(self):
        """Test IPv4 address properties."""
        addr = IPv4Address('192.168.1.1')
        assert addr.version == 4
        assert addr.max_prefixlen == 32
        assert addr.is_private
        assert addr.is_private
        assert not addr.is_loopback
        assert not addr.is_link_local
        assert not addr.is_multicast
        assert not addr.is_reserved
        assert not addr.is_unspecified
    
    def test_ipv6_properties(self):
        """Test IPv6 address properties."""
        addr = IPv6Address('2001:db8::1')
        assert addr.version == 6
        assert addr.max_prefixlen == 128
        assert not addr.is_private
        assert not addr.is_private
        assert not addr.is_loopback
        assert not addr.is_link_local
        assert not addr.is_multicast
        assert not addr.is_reserved
        assert not addr.is_unspecified
    
    def test_loopback_addresses(self):
        """Test loopback addresses."""
        ipv4_loopback = IPv4Address('127.0.0.1')
        ipv6_loopback = IPv6Address('::1')
        
        assert ipv4_loopback.is_loopback
        assert ipv6_loopback.is_loopback
    
    def test_link_local_addresses(self):
        """Test link-local addresses."""
        ipv4_link_local = IPv4Address('169.254.1.1')
        ipv6_link_local = IPv6Address('fe80::1')
        
        assert ipv4_link_local.is_link_local
        assert ipv6_link_local.is_link_local
    
    def test_multicast_addresses(self):
        """Test multicast addresses."""
        ipv4_multicast = IPv4Address('224.0.0.1')
        ipv6_multicast = IPv6Address('ff00::1')
        
        assert ipv4_multicast.is_multicast
        assert ipv6_multicast.is_multicast


class TestNetworkComparison:
    """Test network comparison."""
    
    def test_network_equality(self):
        """Test network equality."""
        net1 = IPv4Network('192.168.1.0/24')
        net2 = IPv4Network('192.168.1.0/24')
        net3 = IPv4Network('192.168.1.0/25')
        
        assert net1 == net2
        assert net1 != net3
    
    def test_network_ordering(self):
        """Test network ordering."""
        net1 = IPv4Network('192.168.1.0/24')
        net2 = IPv4Network('192.168.2.0/24')
        net3 = IPv4Network('192.168.1.0/25')
        
        assert net1 < net2
        assert net1 < net3  # Different networks
    
    def test_network_contains(self):
        """Test network contains."""
        network = IPv4Network('192.168.1.0/24')
        addr = IPv4Address('192.168.1.1')
        subnet = IPv4Network('192.168.1.0/25')
        
        assert addr in network
        assert subnet in network
        # Test reverse containment - these should return False or raise TypeError
        try:
            result1 = network in addr
            assert result1 is False
        except TypeError:
            pass  # Expected behavior
        
        try:
            result2 = network in subnet
            assert result2 is False
        except TypeError:
            pass  # Expected behavior


class TestAddressArithmetic:
    """Test address arithmetic."""
    
    def test_address_addition(self):
        """Test address addition."""
        addr = IPv4Address('192.168.1.1')
        next_addr = addr + 1
        assert str(next_addr) == '192.168.1.2'
        
        # Test overflow
        max_addr = IPv4Address('255.255.255.255')
        with pytest.raises(ValueError):
            max_addr + 1
    
    def test_address_subtraction(self):
        """Test address subtraction."""
        addr = IPv4Address('192.168.1.1')
        prev_addr = addr - 1
        assert str(prev_addr) == '192.168.1.0'
        
        # Test underflow
        min_addr = IPv4Address('0.0.0.0')
        with pytest.raises(ValueError):
            min_addr - 1
    
    def test_address_difference(self):
        """Test address difference."""
        addr1 = IPv4Address('192.168.1.2')
        addr2 = IPv4Address('192.168.1.1')
        # Use int() to get numeric difference
        diff = int(addr1) - int(addr2)
        assert diff == 1
        
        diff2 = int(addr2) - int(addr1)
        assert diff2 == -1


class TestNetworkOperations:
    """Test advanced network operations."""
    
    def test_network_supernet_multiple(self):
        """Test network supernet with multiple prefix differences."""
        network = IPv4Network('192.168.1.0/26')
        supernet = network.supernet(prefixlen_diff=2)
        assert str(supernet) == '192.168.1.0/24'
    
    def test_network_subnets_multiple(self):
        """Test network subnets with multiple prefix differences."""
        network = IPv4Network('192.168.1.0/24')
        subnets = list(network.iter_subnets(prefixlen_diff=2))
        assert len(subnets) == 4
        assert str(subnets[0]) == '192.168.1.0/26'
        assert str(subnets[1]) == '192.168.1.64/26'
        assert str(subnets[2]) == '192.168.1.128/26'
        assert str(subnets[3]) == '192.168.1.192/26'
    
    def test_network_address_count(self):
        """Test network address count."""
        network = IPv4Network('192.168.1.0/24')
        assert network.numhosts == 256
        
        network_small = IPv4Network('192.168.1.0/30')
        assert network_small.numhosts == 4
    
    def test_network_host_count(self):
        """Test network host count."""
        network = IPv4Network('192.168.1.0/24')
        assert network.numhosts == 256  # Total addresses
        
        network_small = IPv4Network('192.168.1.0/30')
        assert network_small.numhosts == 4  # Total addresses
