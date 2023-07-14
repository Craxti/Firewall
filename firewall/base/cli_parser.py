import argparse


class BwCli:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.help_defaults = """
        Defaults:
            Outbound connections will be allowed on all ports to all hosts.
            Inbound connections will be limited to related outbound traffic.
            DHCP will be enabled.
            Ping responses will be enabled.
            Unsolicited inbound connections will be dropped.

        """
        self.about = """
        Version: firewall 3.0
        Authors: Alexksandr Fetisov
        Email: fetis.dev@gmail.com
        """

        self.logo = """Firewall""".format(bb='\\' * 53, tb='/' * 53)

        self.parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                              description="A python framework to automate firewall setup.\n\n".format(
                                                  logo=self.logo) + self.help_defaults)
        self.parser.add_argument("-V", "--version", action="version", version='%(prog)s |firewall| (Version 1.0)',
                                 help="Display Version")
        self.parser.add_argument("-v", "--verbose", action="store_true", help="Verbose Mode")
        self.parser.add_argument("-r", "--reset", action="store_true", help="Send TCP RST instead of dropping packet.")
        self.parser.add_argument("-p", "--disallow_ping", action="store_true", help="Disallow incoming PING")
        self.parser.add_argument("-i", "--allow_outbound_icmp", action="store_true", help="Don't restrict ICMP types")
        self.parser.add_argument("-d", "--disallow_dhcp", action="store_true", help="Disallow DHCP")
        self.parser.add_argument("-w", "--windows_config",
                                 help="Generate Windows Configuration. Usage: firewall -w config.ps1")
        self.parser.add_argument("-ot", "--tcp_ports_out", help="Comma separated list of allowed TCP ports outbound")
        self.parser.add_argument("-ou", "--udp_ports_out", help="Comma separated list of allowed UDP ports outbound")
        self.parser.add_argument("-it", "--tcp_ports_in", help="Comma separated list of allowed TCP ports inbound")
        self.parser.add_argument("-iu", "--udp_ports_in", help="Comma separated list of allowed UDP ports inbound")
        self.parser.add_argument("-oh", "--outbound_hosts",
                                 help="Restrict outbound to specified hosts. -oh 192.168.3.0/24,192.168.4.0/24")
        self.parser.add_argument("-ih", "--inbound_hosts",
                                 help="Restrict outbound to specified hosts. -ih 192.168.3.0/24,192.168.4.0/24")
        self.parser.add_argument("-eh", "--exclude_hosts", help="Exclude hosts -eh 192.168.3.0/24")
        self.parser.add_argument("-l", "--log_exceptions", action="store_true", help="Log Exceptions")
        self.parser.add_argument("-s", "--simulate", help="Simulate only.", action="store_true")
        self.parser.add_argument("-q", "--quiet", action="store_true", help="Quiet (don't display status messages")
        self.parser.add_argument("-D", "--deny_all", action="store_true", help="Absolute Deny all")
        self.parser.add_argument("-A", "--allow_all", action="store_true", help="Absolute allow all")
        self.parser.add_argument("-F", "--flush", action="store_true", help="Flush IPTables")
        self.parser.add_argument("-S", "--show_rules", action="store_true", help="Show rules after setting")
        self.parser.add_argument("--wizard", action="store_true", help="Addressing and firewall wizard mode")
        self.parser.add_argument("-c", "--config", help="Configuration for firewall")
        self.parser.add_argument("--info", help="About firewall", action="store_true")

    def parse_args(self):
        self.args = self.parser.parse_args()

    def firewall_info(self):
        out = self.logo + '\n' + self.about
        return out


class BsCli:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.help_defaults = """
        BLUESCAN works with Firewall and will identify all hosts on the network that are alive.

        By passing a config, BLUESCAN will identify all alive hosts on the target networks specified in the 
        configuration file.
        """
        self.about = """
        Version: Bluescan 1.0
        Authors: Austin Taylor, Nick Lupien
        Email: git@austintaylor.io, nick.lupien@infiniteloops.net
        """

        self.logo = """
         {tb}
        |  _____ __    _____ _____ _ _ _ _____ __    __      |
        | |  __ |  |  |  |  |   __| | | |  -  |  |  |  |     |
        | |  __-|  |__|  |  |   __| | | |     |  |__|  |__   |
        | |_____|_____|_____|_____|_____|__|__|_____|_____|  |
        |               ****BLUESCAN****                     |
        |                                                    |
         {bb}
        """.format(bb='\\' * 53, tb='/' * 53)

        self.parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                              description="A Firewall module to identify alive hosts setup.\n\n".format(
                                                  logo=self.logo) + self.help_defaults)
        self.parser.add_argument("-V", "--version", action="version", version='%(prog)s |BLUESCAN| (Version 1.0)',
                                 help="Display Version")
        self.parser.add_argument("-t", "--target_range", help="Target of range to identify keep host(s)")
        self.parser.add_argument("-e", "--exclude", help="Devices not to communicate with during scan")
        self.parser.add_argument("-r", "--random", help="Randomize IP addresses during scanning")
        self.parser.add_argument("-v", "--verbose", action="store_true", help="Verbose Mode")
        self.parser.add_argument("-o", "--output", help="Filename to write to")
        self.parser.add_argument("-c", "--config", help="Configuration for firewall")
        self.parser.add_argument("--threads", help="Set how many threads to use (can speed up scan)")
        self.parser.add_argument("--info", help="About Bluescan", action="store_true")

    def parse_args(self):
        self.args = self.parser.parse_args()

    def firewall_info(self):
        out = self.logo + '\n' + self.about
        return out
