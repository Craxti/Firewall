#!/usr/bin/env python3
"""
Advanced Firewall Usage Examples
================================

This file demonstrates advanced usage patterns for the Firewall framework.
Perfect for open source projects and production environments.
"""

import os
import sys
from pathlib import Path

# Add the parent directory to the path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from firewall.interact.set_firewall import SetFirewall
from firewall.windows.adapter import WindowsFirewallAdapter
from firewall.host_config.confighost import ConfigHost


def linux_advanced_firewall_setup():
    """
    Advanced Linux firewall setup with comprehensive rules.
    """
    print("🔥 Setting up advanced Linux firewall...")
    
    # Initialize firewall with verbose output
    firewall = SetFirewall(verbose=1, execute=False)  # Set to True for real execution
    
    # Basic security setup
    firewall.flush_rules()
    firewall.set_policy('DROP')
    firewall.allow_localhost()
    firewall.allow_related_conn()
    
    # Allow essential services
    firewall.allow_dhcp()
    firewall.allow_ping()
    
    # Allow SSH (port 22)
    firewall.allow_network_transport(
        direction='inbound',
        protocol='tcp',
        ports=[22],
        networks='0.0.0.0/0',
        policy='ACCEPT'
    )
    
    # Allow HTTP/HTTPS
    firewall.allow_network_transport(
        direction='inbound',
        protocol='tcp',
        ports=[80, 443],
        networks='0.0.0.0/0',
        policy='ACCEPT'
    )
    
    # Allow DNS
    firewall.allow_network_transport(
        direction='outbound',
        protocol='udp',
        ports=[53],
        networks='0.0.0.0/0',
        policy='ACCEPT'
    )
    
    # Block specific malicious networks
    firewall.set_nostrike([
        '192.168.1.100/32',  # Block specific IP
        '10.0.0.0/8'         # Block entire network
    ])
    
    print(f"✅ Generated {len(firewall.command_list)} firewall rules")
    return firewall


def windows_advanced_firewall_setup():
    """
    Advanced Windows firewall setup with comprehensive rules.
    """
    print("🪟 Setting up advanced Windows firewall...")
    
    # Initialize Windows firewall adapter
    windows_firewall = WindowsFirewallAdapter(verbose=1, execute=False)  # Set to True for real execution
    
    # Basic security setup
    windows_firewall.flush_rules()
    windows_firewall.set_policy('DROP')
    windows_firewall.allow_related_conn()
    
    # Allow essential services
    windows_firewall.allow_dhcp()
    windows_firewall.allow_ping()
    
    # Allow RDP (port 3389)
    windows_firewall.allow_network_transport(
        direction='inbound',
        protocol='tcp',
        ports=[3389],
        networks='192.168.1.0/24',  # Only from local network
        policy='ACCEPT'
    )
    
    # Allow HTTP/HTTPS
    windows_firewall.allow_network_transport(
        direction='inbound',
        protocol='tcp',
        ports=[80, 443],
        networks='0.0.0.0/0',
        policy='ACCEPT'
    )
    
    # Allow outbound HTTPS
    windows_firewall.allow_network_transport(
        direction='outbound',
        protocol='tcp',
        ports=[443],
        networks='0.0.0.0/0',
        policy='ACCEPT'
    )
    
    # Block specific networks
    windows_firewall.set_nostrike([
        '192.168.1.100/32',
        '10.0.0.0/8'
    ])
    
    print(f"✅ Generated {len(windows_firewall.command_list)} Windows firewall rules")
    return windows_firewall


def configuration_based_setup():
    """
    Firewall setup based on configuration file.
    """
    print("📝 Setting up firewall from configuration...")
    
    # Create a sample configuration
    config_content = """
[local_config]
iface=eth0
rh_host=firewall-server
rh_ipaddr=192.168.1.100
netmask=255.255.255.0
gateway_addr=192.168.1.1
dns=8.8.8.8

[firewall_config]
target_range=10.0.0.0/8
target_range=172.16.0.0/12
trusted_range=192.168.1.0/24
trusted_range=192.168.0.0/16
nostrike=192.168.1.5/32
nostrike=10.0.0.100/32

[security_settings]
log_exceptions=true
disallow_ping=false
allow_outbound_icmp=true
disallow_dhcp=false
"""
    
    # Write configuration to file
    config_file = Path("temp_config.ini")
    config_file.write_text(config_content)
    
    try:
        # Load configuration
        config_host = ConfigHost(config_in=str(config_file), VERBOSE=True)
        
        # Apply configuration-based rules
        firewall = config_host.set_firewall
        
        print("✅ Configuration loaded successfully")
        print(f"📊 Generated {len(firewall.command_list)} rules from configuration")
        
        return config_host
        
    finally:
        # Clean up
        if config_file.exists():
            config_file.unlink()


def network_security_scanner():
    """
    Advanced network security scanning and firewall rule generation.
    """
    print("🔍 Performing network security analysis...")
    
    # Simulate network analysis
    suspicious_ips = [
        '192.168.1.100',
        '10.0.0.50',
        '172.16.0.25'
    ]
    
    trusted_networks = [
        '192.168.1.0/24',
        '192.168.0.0/16'
    ]
    
    # Create firewall rules based on analysis
    firewall = SetFirewall(verbose=1, execute=False)
    
    # Block suspicious IPs
    for ip in suspicious_ips:
        firewall.set_nostrike([f"{ip}/32"])
        print(f"🚫 Blocking suspicious IP: {ip}")
    
    # Allow trusted networks
    for network in trusted_networks:
        firewall.allow_network_transport(
            direction='inbound',
            protocol='tcp',
            networks=network,
            policy='ACCEPT'
        )
        print(f"✅ Allowing trusted network: {network}")
    
    print(f"🛡️ Security analysis complete - {len(firewall.command_list)} rules generated")
    return firewall


def production_ready_setup():
    """
    Production-ready firewall configuration with best practices.
    """
    print("🏭 Setting up production-ready firewall...")
    
    firewall = SetFirewall(verbose=1, execute=False)
    
    # Production security baseline
    firewall.flush_rules()
    firewall.set_policy('DROP')
    firewall.allow_localhost()
    firewall.allow_related_conn()
    
    # Essential services
    firewall.allow_dhcp()
    
    # Web server rules
    firewall.allow_network_transport(
        direction='inbound',
        protocol='tcp',
        ports=[80, 443, 8080],
        networks='0.0.0.0/0',
        policy='ACCEPT'
    )
    
    # Database access (restricted)
    firewall.allow_network_transport(
        direction='inbound',
        protocol='tcp',
        ports=[3306, 5432],
        networks='192.168.1.0/24',  # Only from local network
        policy='ACCEPT'
    )
    
    # SSH access (restricted)
    firewall.allow_network_transport(
        direction='inbound',
        protocol='tcp',
        ports=[22],
        networks='192.168.1.0/24',  # Only from local network
        policy='ACCEPT'
    )
    
    # Outbound HTTPS for updates
    firewall.allow_network_transport(
        direction='outbound',
        protocol='tcp',
        ports=[443],
        networks='0.0.0.0/0',
        policy='ACCEPT'
    )
    
    # DNS resolution
    firewall.allow_network_transport(
        direction='outbound',
        protocol='udp',
        ports=[53],
        networks='0.0.0.0/0',
        policy='ACCEPT'
    )
    
    # Block common attack vectors
    firewall.set_nostrike([
        '0.0.0.0/0'  # Block everything else by default
    ])
    
    print(f"🏭 Production setup complete - {len(firewall.command_list)} security rules")
    return firewall


def main():
    """
    Main function demonstrating all advanced usage patterns.
    """
    print("🚀 Firewall Framework - Advanced Usage Examples")
    print("=" * 50)
    
    # Example 1: Linux Advanced Setup
    print("\n1️⃣ Linux Advanced Firewall Setup")
    linux_firewall = linux_advanced_firewall_setup()
    
    # Example 2: Windows Advanced Setup
    print("\n2️⃣ Windows Advanced Firewall Setup")
    windows_firewall = windows_advanced_firewall_setup()
    
    # Example 3: Configuration-based Setup
    print("\n3️⃣ Configuration-based Setup")
    config_setup = configuration_based_setup()
    
    # Example 4: Network Security Scanner
    print("\n4️⃣ Network Security Analysis")
    security_firewall = network_security_scanner()
    
    # Example 5: Production Ready Setup
    print("\n5️⃣ Production Ready Configuration")
    production_firewall = production_ready_setup()
    
    print("\n🎉 All examples completed successfully!")
    print("💡 Set execute=True in the firewall objects to apply rules")
    print("⚠️  Always test in a safe environment first!")


if __name__ == "__main__":
    main()
