"""
Windows adapter for firewall management using PowerShell commands.
This module provides a compatible interface with the Linux iptables firewall commands.
"""

import subprocess
import os
import re
from ..interact.set_firewall import SetFirewall
from ..base.cli_parser import BwCli


class WindowsFirewallAdapter(BwCli):
    """
    Windows firewall adapter for managing Windows Firewall rules via PowerShell.
    """

    def __init__(self, config_in=None, verbose=0, log_response=False, execute=True):
        super().__init__(verbose=verbose)

        self.config_in = config_in
        self.verbose = verbose
        self.execute = execute
        self.command_list = []

        self.rule_counter = 0

    def run_command(self, cmd, wait=False):
        """Execute PowerShell command."""
        powershell_cmd = f'powershell.exe -Command "{cmd}"'

        if self.verbose > 1:
            print(f"$ {powershell_cmd}")

        if wait:
            process = subprocess.Popen(powershell_cmd, shell=True)
            process.wait()
            return None
        else:
            output = subprocess.check_output(powershell_cmd, shell=True)
            output_str = output.decode('utf-8', errors='replace')

            if self.verbose > 1:
                print(output_str)

            return output_str

    def process_commands(self):
        """Process all queued commands."""
        if not self.execute:
            return

        for cmd in self.command_list:
            self.run_command(cmd)

        if self.verbose:
            print("[+] Windows firewall rules applied")

    def _generate_rule_name(self, prefix="FirewallRule"):
        """Generate unique rule name."""
        self.rule_counter += 1
        return f"{prefix}_{self.rule_counter}"

    def flush_rules(self):
        """Remove all firewall rules."""
        cmd = "Remove-NetFirewallRule -PolicyStore ActiveStore -Name 'FirewallRule_*' -ErrorAction SilentlyContinue"
        self.command_list.append(cmd)

        if self.verbose:
            print("[+] Flushing Windows firewall rules")

    def set_policy(self, policy):
        """Set default firewall policy."""
        action = "Allow" if policy == "ACCEPT" else "Block"

        inbound_cmd = f"Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction {action}"
        outbound_cmd = f"Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction {action}"

        self.command_list.append(inbound_cmd)
        self.command_list.append(outbound_cmd)

        if self.verbose:
            print(f"[+] Setting default policy to {policy}")

        return [inbound_cmd, outbound_cmd]

    def allow_dhcp(self):
        """Allow DHCP traffic."""
        inbound_rule = f"""
        New-NetFirewallRule -Name '{self._generate_rule_name("DHCP_In")}' -DisplayName 'Allow DHCP In' `
        -Direction Inbound -Protocol UDP -LocalPort 67,68 -RemotePort 67,68 -Action Allow
        """

        outbound_rule = f"""
        New-NetFirewallRule -Name '{self._generate_rule_name("DHCP_Out")}' -DisplayName 'Allow DHCP Out' `
        -Direction Outbound -Protocol UDP -LocalPort 67,68 -RemotePort 67,68 -Action Allow
        """

        self.command_list.append(inbound_rule)
        self.command_list.append(outbound_rule)

        if self.verbose:
            print("[+] Allowing DHCP traffic")

    def allow_ping(self):
        """Allow ICMP ping traffic."""
        inbound_echo_request = f"""
        New-NetFirewallRule -Name '{self._generate_rule_name("ICMP_In_EchoRequest")}' -DisplayName 'Allow ICMPv4 In Echo Request' `
        -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow
        """

        inbound_echo_reply = f"""
        New-NetFirewallRule -Name '{self._generate_rule_name("ICMP_In_EchoReply")}' -DisplayName 'Allow ICMPv4 In Echo Reply' `
        -Direction Inbound -Protocol ICMPv4 -IcmpType 0 -Action Allow
        """

        outbound_echo_request = f"""
        New-NetFirewallRule -Name '{self._generate_rule_name("ICMP_Out_EchoRequest")}' -DisplayName 'Allow ICMPv4 Out Echo Request' `
        -Direction Outbound -Protocol ICMPv4 -IcmpType 8 -Action Allow
        """

        outbound_echo_reply = f"""
        New-NetFirewallRule -Name '{self._generate_rule_name("ICMP_Out_EchoReply")}' -DisplayName 'Allow ICMPv4 Out Echo Reply' `
        -Direction Outbound -Protocol ICMPv4 -IcmpType 0 -Action Allow
        """

        self.command_list.append(inbound_echo_request)
        self.command_list.append(inbound_echo_reply)
        self.command_list.append(outbound_echo_request)
        self.command_list.append(outbound_echo_reply)

        if self.verbose:
            print("[+] Allowing ICMP ping traffic")

    def disallow_ping(self):
        """Block incoming ICMP ping requests."""
        rule = f"""
        New-NetFirewallRule -Name '{self._generate_rule_name("ICMP_Block_In")}' -DisplayName 'Block ICMPv4 In Echo Request' `
        -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Block
        """

        self.command_list.append(rule)

        if self.verbose:
            print("[+] Blocking incoming ICMP ping requests")

    def allow_localhost(self):
        """Allow localhost traffic (default in Windows)."""
        if self.verbose:
            print("[+] Localhost traffic is allowed by default in Windows")

    def allow_related_conn(self):
        """Allow related connections."""
        inbound_rule = f"""
        New-NetFirewallRule -Name '{self._generate_rule_name("Related_In")}' -DisplayName 'Allow Related Connections In' `
        -Direction Inbound -Enabled True -Action Allow -EdgeTraversalPolicy Allow
        """

        outbound_rule = f"""
        New-NetFirewallRule -Name '{self._generate_rule_name("Related_Out")}' -DisplayName 'Allow Related Connections Out' `
        -Direction Outbound -Enabled True -Action Allow
        """

        self.command_list.append(inbound_rule)
        self.command_list.append(outbound_rule)

        if self.verbose:
            print("[+] Allowing related connections")

    def allow_network_transport(self, direction=None, trusted=False, protocol='tcp', ports=None, networks='0.0.0.0/0', policy='ACCEPT'):
        """Allow network transport with specified parameters."""
        if direction not in ['inbound', 'outbound']:
            raise ValueError("Direction must be 'inbound' or 'outbound'")

        if protocol not in ['tcp', 'udp']:
            raise ValueError("Protocol must be 'tcp' or 'udp'")

        if ports is None:
            ports = []

        if ports:
            ports_str = ','.join([str(p) for p in ports])
        else:
            ports_str = None

        action = "Allow" if policy == "ACCEPT" else "Block"

        if isinstance(networks, str):
            networks = [networks]

        for network in networks:
            rule_name = self._generate_rule_name(f"{protocol.upper()}_{direction}")
            display_name = f"{'Allow' if action == 'Allow' else 'Block'} {protocol.upper()} {direction}"

            cmd = f"""
            New-NetFirewallRule -Name '{rule_name}' -DisplayName '{display_name}' `
            -Direction {'Inbound' if direction == 'inbound' else 'Outbound'} `
            -Protocol {protocol.upper()} """

            if ports_str:
                if direction == 'inbound':
                    cmd += f"-LocalPort {ports_str} "
                else:
                    cmd += f"-RemotePort {ports_str} "

            if network != '0.0.0.0/0':
                if (direction == 'inbound' and not trusted) or (direction == 'outbound' and trusted):
                    cmd += f"-RemoteAddress {network} "
                else:
                    cmd += f"-LocalAddress {network} "

            cmd += f"-Action {action}"

            self.command_list.append(cmd)

        if self.verbose:
            net_str = ', '.join(networks)
            ports_info = f" for ports {ports_str}" if ports_str else ""
            print(f"[+] {'Allowing' if action == 'Allow' else 'Blocking'} {protocol.upper()} {direction} {ports_info} for {net_str}")

    def all_icmp(self, status=1):
        """Allow all ICMP traffic."""
        if status == 1:
            outbound_rule = f"""
            New-NetFirewallRule -Name '{self._generate_rule_name("ICMP_All_Out")}' -DisplayName 'Allow All ICMPv4 Out' `
            -Direction Outbound -Protocol ICMPv4 -Action Allow
            """

            self.command_list.append(outbound_rule)

            if self.verbose:
                print("[+] Allowing all outbound ICMP traffic")
        else:
            outbound_echo_request = f"""
            New-NetFirewallRule -Name '{self._generate_rule_name("ICMP_Out_EchoRequest")}' -DisplayName 'Allow ICMPv4 Out Echo Request' `
            -Direction Outbound -Protocol ICMPv4 -IcmpType 8 -Action Allow
            """

            outbound_echo_reply = f"""
            New-NetFirewallRule -Name '{self._generate_rule_name("ICMP_Out_EchoReply")}' -DisplayName 'Allow ICMPv4 Out Echo Reply' `
            -Direction Outbound -Protocol ICMPv4 -IcmpType 0 -Action Allow
            """

            self.command_list.append(outbound_echo_request)
            self.command_list.append(outbound_echo_reply)

            if self.verbose:
                print("[+] Allowing outbound ICMP echo request and reply")

    def all_icmp_network(self, status=1, networks='0.0.0.0/0'):
        """Allow ICMP traffic to specific networks."""
        # Convert networks to list
        if isinstance(networks, str):
            networks = [networks]

        for network in networks:
            if status == 1:
                rule = f"""
                New-NetFirewallRule -Name '{self._generate_rule_name("ICMP_Net_Out")}' -DisplayName 'Allow ICMPv4 Out to Network' `
                -Direction Outbound -Protocol ICMPv4 -RemoteAddress {network} -Action Allow
                """

                self.command_list.append(rule)
            else:
                echo_request = f"""
                New-NetFirewallRule -Name '{self._generate_rule_name("ICMP_Net_Out_EchoReq")}' -DisplayName 'Allow ICMPv4 Out Echo Request to Network' `
                -Direction Outbound -Protocol ICMPv4 -IcmpType 8 -RemoteAddress {network} -Action Allow
                """

                echo_reply = f"""
                New-NetFirewallRule -Name '{self._generate_rule_name("ICMP_Net_Out_EchoRep")}' -DisplayName 'Allow ICMPv4 Out Echo Reply to Network' `
                -Direction Outbound -Protocol ICMPv4 -IcmpType 0 -RemoteAddress {network} -Action Allow
                """

                self.command_list.append(echo_request)
                self.command_list.append(echo_reply)

            if self.verbose:
                print(f"[+] Allowing {'all' if status == 1 else 'ping'} outbound ICMP traffic to {network}")

    def set_nostrike(self, networks=None):
        """Block traffic to/from specified networks."""
        if networks is None:
            networks = []

        if not networks:
            return

        if isinstance(networks, str):
            networks = [networks]

        for network in networks:
            inbound_rule = f"""
            New-NetFirewallRule -Name '{self._generate_rule_name("Block_In")}' -DisplayName 'Block Inbound from Network' `
            -Direction Inbound -RemoteAddress {network} -Action Block
            """

            outbound_rule = f"""
            New-NetFirewallRule -Name '{self._generate_rule_name("Block_Out")}' -DisplayName 'Block Outbound to Network' `
            -Direction Outbound -RemoteAddress {network} -Action Block
            """

            self.command_list.append(inbound_rule)
            self.command_list.append(outbound_rule)

            if self.verbose:
                print(f"[+] Blocking all traffic to/from {network}")

    def show_rules(self):
        """Display current firewall rules."""
        cmd = "Get-NetFirewallRule | Where-Object { $_.Name -like 'FirewallRule_*' } | Format-Table -Property DisplayName, Direction, Action, Enabled"
        self.run_command(cmd, wait=True)

    def deny_all(self):
        """Block all traffic (default deny)."""
        self.flush_rules()

        self.set_policy('DROP')

        self.allow_related_conn()

        if self.verbose:
            print("[+] Blocking all traffic (default deny)")

    def allow_all(self):
        """Allow all traffic (default allow)."""
        self.flush_rules()

        self.set_policy('ACCEPT')

        if self.verbose:
            print("[+] Allowing all traffic (default allow)")

    def allow_outbound_transport(self, protocol='tcp', ports=None):
        """Allow outbound transport."""
        if ports is None:
            ports = []

        self.allow_network_transport(
            direction='outbound',
            protocol=protocol,
            ports=ports,
            networks='0.0.0.0/0',
            policy='ACCEPT'
        ) 