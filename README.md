# Firewall

A universal tool for managing firewalls in Linux and Windows. Allows you to quickly and conveniently configure firewall rules, ensuring the security of your system.

## Features

- Manage the firewall via a single interface for Linux (iptables) and Windows (Windows Firewall)
- Configure rules for incoming and outgoing traffic
- Block and allow specific ports, protocols, and IP addresses
- Support for configuration via a configuration file
- Simulate the application of rules for preliminary checking
- Advanced logging capabilities
- Wizard for interactive configuration

## Requirements

- Python 3.6 or higher
- Linux: iptables
- Windows: PowerShell 3.0 or higher

## Installation

### Install from PyPI

```bash
pip install firewall
```

### Install from source

```bash
git clone https://github.com/fetis/firewall.git
cd firewall
pip install -e .
```

## Quick Start

### Basic Commands

#### Allow All Traffic

```bash
sudo firewall --allow-all
```

#### Deny All Traffic (while Allowing Established Connections)

```bash
sudo firewall --deny-all
```

#### Set Basic Security Rules

```bash
sudo firewall
```

### Manage Network Traffic

#### Allow Incoming Connections on a Specific Port

```bash
sudo firewall -ti 80,443
```

#### Allow Outgoing Connections on a Specific Port

```bash
sudo firewall -to 53,80,443
```

#### Allow UDP Traffic

```bash
sudo firewall -ui 53
```

### Working with IP addresses and networks

#### Allow incoming traffic from a specific IP address

```bash
sudo firewall -i 192.168.1.10/32
```

#### Allow outgoing traffic to a specific network

```bash
sudo firewall -o 10.0.0.0/8
```

#### Block traffic for specific networks

```bash
sudo firewall -x 192.168.1.100/32,10.0.0.5/32
```

### Windows examples

On Windows, the commands have the same syntax, but require administrator rights to run.

```powershell
# Run PowerShell as Administrator
firewall --allow-all
```

## Advanced Usage

### Using a Configuration File

Create a configuration file:

```ini
[local_config]
iface=eth0
rh_host=myserver
rh_ipaddr=192.168.1.100
netmask=255.255.255.0
gateway_addr=192.168.1.1
dns=8.8.8.8

[firewall_config]
target_range=10.0.0.0/8
target_range=172.16.0.0/12
trusted_range=192.168.1.0/24
nostrike=192.168.1.5/32
```

Apply configuration:

```bash
sudo firewall -c config.ini
```

### Interactive configuration mode

```bash
sudo firewall --wizard
```

### Simulate rules before applying

```bash
sudo firewall -ti 80,443 -i 192.168.1.0/24 --simulate
```

## Description of command line arguments

| Argument | Description |
|----------|----------|
| `-to, --tcp-ports-out` | Allow outgoing TCP traffic to the specified ports |
| `-ti, --tcp-ports-in` | Allow incoming TCP traffic to the specified ports |
| `-uo, --udp-ports-out` | Allow outgoing UDP traffic to specified ports |
| `-ui, --udp-ports-in` | Allow incoming UDP traffic to specified ports |
| `-i, --inbound-hosts` | Allow incoming traffic from specified hosts/networks |
| `-o, --outbound-hosts` | Allow outgoing traffic to specified hosts/networks |
| `-x, --exclude-hosts` | Block traffic for specified hosts/networks |
| `-c, --config` | Specify configuration file |
| `-w, --windows-config` | Specify Windows configuration file |
| `-f, --flush` | Reset all rules |
| `-r, --reset` | Reset connections |
| `-s, --simulate` | Simulate applying rules without actually applying them |
| `-q, --quiet` | Quiet mode (no output) |
| `-p, --disallow-ping` | Deny incoming ping requests |
| `-icmp, --allow-outbound-icmp` | Allow outbound ICMP requests |
| `-d, --disallow-dhcp` | Deny DHCP |
| `-l, --log-exceptions` | Log exceptions |
| `--deny-all` | Deny all traffic |
| `--allow-all` | Allow all traffic |
| `--info` | Show firewall information |
| `--show-rules` | Show current rules |
| `--wizard` | Run the wizard |

## Usage examples for different scenarios

### Web server setup

```bash
# Allow HTTP, HTTPS and SSH
sudo firewall -ti 80,443,22 -x 10.0.0.0/8
```

### DNS server setup

```bash
# Allow DNS and DHCP
sudo firewall -ti 53 -ui 53,67,68
```

### Workstation setup

```bash
# Basic rules with outgoing web traffic allowed
sudo firewall -to 80,443,53 -uo 53 -p
```

## Support for different operating systems

### Linux

On Linux, the application uses iptables to manage the firewall. Root privileges (sudo) are required to work.

### Windows

On Windows, the application uses Windows Firewall via PowerShell. Administrator rights are required to work.

Windows version features:
- PowerShell commands are used to apply rules instead of iptables
- Some Linux-specific features may work differently
- PowerShell 3.0 or higher is required

## Development and testing

### Setting up the development environment

```bash
# Cloning the repository
git