from firewall.utils.shell import Bcolors
from firewall.environment.rhel import config
from firewall.utils import ipaddr
from firewall.utils.shell import Interact
import re

class Validation(object):
    def __init__(self, config=None, verbose=False, field_type=None):
        if config is not None:
            self.config = config
        self.verbose = verbose
        if field_type is None:
            self.field_type = {'iface': 'eth_iface',
                               'rh_ipaddr': 'ip',
                               'win_ipaddr': 'ip',
                               'rh_mac': 'mac',
                               'dns': 'ip',
                               'cidr_prefix': 'int',
                               'rh_host': 'hostname',
                               'win_host': 'hostname',
                               'gateway_addr': 'ip',
                               'target_range': 'subnet',
                               'nostrike': 'subnet',
                               'trusted_range': 'subnet',
                               'trusted_host': 'subnet'}
        else:
            self.field_type = field_type

    def hostname_check(self, data):
        valid = False
        if re.match('^[a-zA-Z0-9-]*$', data):
            valid = True
        return valid

    def eth_iface_check(self, data):
        valid = False
        all_iface = [iface for iface in Interact().run_command("nmcli d | cut -d' ' -f 1").split('\n')[1:] if iface != '']
        if data in all_iface:
            valid = True
        return valid

    def mac_check(self, data):
        valid = False
        if data == '*':
            valid = True
        if re.match("((?!(00([:-]|$)){6}|(FF([:-]|$)){6}|(88[:-]){4}87[:-]88)[0-9A-F]{2}([:-]|$)){6}", data):
            valid = True
        return valid

    def cidr_prefix_check(self, data):
        try:
            if int(data) > 1 and int(data) <= 32:
                return True
        except:
            return False
        return False

    def network_validator(self, network, boolean=True):
        try:
            ipaddr.IPNetwork(network)
        except Exception as e:
            if boolean:
                return False
            raise Exception("Please validate your subnet. Valid input: 192.168.0.0/24")
        return True

    def ip_validator(self, network, boolean=True):
        try:
            ipaddr.IPAddress(network)
        except Exception as e:
            if boolean:
                return False
            raise Exception("Please validate your IP Address. Valid input: 192.168.0.0/24")
        return True

    def validate(self):
        if self.config is not None:
            config_obj = config(config=self.config)
        key_map = self.field_type
        captured_errors = []
        missing_keys = []
        print("{bold}[VALIDATING CONFIGURATION]{endc}\n".format(bold=Bcolors.OKBLUE, endc=Bcolors.ENDC))
        for key in key_map:
            try:
                conf_key = config_obj.configs.get(key)
                if conf_key is None:
                    missing_keys.append(key)
                if conf_key:
                    for value in config_obj.configs.get(key):
                        valid = False
                        if key_map[key] == 'ip':
                            valid = self.ip_validator(value)
                        elif key_map[key] == 'subnet':
                            valid = self.network_validator(value)
                        elif key_map[key] == 'int':
                            valid = value.isdigit()
                        elif key_map[key] == 'hostname':
                            valid = self.hostname_check(value)
                        elif key_map[key] == 'mac':
                            valid = self.mac_check(value)
                        elif key_map[key] == 'eth_iface':
                            valid = self.eth_iface_check(value)
                        else:
                            pass
                        if valid == False:
                            FAIL = "[{red}FAIL{endred}] in configuration :: Check {key} setting: {value}".format(
                                key=key, value=value, red=Bcolors.FAIL, endred=Bcolors.ENDC)
                            captured_errors.append(FAIL)
                            if self.verbose:
                                print(FAIL)
                        else:
                            if self.verbose:
                                print("[{green}OK{endgreen}] {value} is a valid setting for {key}".format(value=value,
                                                                                                          key=key,
                                                                                                          green=Bcolors.OKGREEN,
                                                                                                          endgreen=Bcolors.ENDC))
            except Exception as e:
                print(e)
        if missing_keys:
            for key in missing_keys:
                WARNING = "{warning_c}[WARNING]{warning_end} No setting for {key} was found.".format(
                    warning_c=Bcolors.WARNING, warning_end=Bcolors.ENDC, key=key)
                print(WARNING)

        if captured_errors:
            CONFIG_ERROR = "{error_count} errors detect. Please verify your settings in {config}".format(
                error_count=len(captured_errors), config=self.config)
            if self.verbose:
                print("\n\n" + "=" * 10 + 'ERROR REPORT' + "=" * 10)
                for error in captured_errors:
                    print(error)
            print(CONFIG_ERROR)
            exit()
        else:
            print("{newline}[{green}VALID CONFIG{endgreen}] No Errors Detected.".format(newline="=" * 30 + '\n',
                                                                                        green=Bcolors.OKGREEN,
                                                                                        endgreen=Bcolors.ENDC))
        return
