import subprocess
import os
import sys
import logging
import platform
from firewall.utils.whiptail import Whiptail


logger = logging.getLogger("firewall")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

try:
    if platform.system().lower() == 'windows':
        log_file = os.path.join(os.environ.get('LOCALAPPDATA', 'C:\\Temp'), 'firewall.log')
    else:
        log_file = '/var/log/firewall.log'
    
    if not os.access(os.path.dirname(log_file), os.W_OK):
        import tempfile
        log_file = os.path.join(tempfile.gettempdir(), 'firewall.log')
    
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
except (IOError, PermissionError) as e:
    logger.warning(f"{str(e)}")


class CommandError(Exception):
    """Exception for command execution errors."""
    
    def __init__(self, command, output=None, return_code=None):
        self.command = command
        self.output = output
        self.return_code = return_code
        error_msg = f"Command failed: {command}"
        if return_code is not None:
            error_msg += f", return code: {return_code}"
        if output:
            error_msg += f", output: {output}"
        super().__init__(error_msg)


class Interact:
    def run_command(self, cmd, VERBOSE=0, DEBUG=False, wait=False):
        """
        Executes a shell command with improved error handling.

        Args:
            cmd: The command to execute
            VERBOSE: The verbosity level (0-2)
            DEBUG: Debugging flag
            wait: Wait for the command to complete

        Returns:
            The output of the command, or None if wait=True

        Raises:
            CommandError: If the command exited with an error
        """
        if VERBOSE < 2:
            stderr_redirect = " 2>/dev/null" if platform.system().lower() != 'windows' else " 2>nul"
            cmd += stderr_redirect
            
        if DEBUG or VERBOSE > 1:
            print(f"$ {cmd}")
            logger.debug(f"Executing the command: {cmd}")
            
        try:
            if wait:
                logger.debug(f"Starting command with wait: {cmd}")
                process = subprocess.Popen(cmd, shell=True)
                return_code = process.wait()
                
                if return_code != 0:
                    logger.error(f"Command failed with error: {cmd}, return code: {return_code}")
                    if VERBOSE > 0:
                        print(f"[-] Error executing command: {cmd}, return code: {return_code}")
                    raise CommandError(cmd, return_code=return_code)
                
                return None
            else:
                logger.debug(f"Run command: {cmd}")
                try:
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    output_str = stdout.decode('utf-8', errors='replace')
                    
                    if DEBUG or VERBOSE > 1:
                        print(output_str)
                        
                    logger.debug(f"Command execution result: {output_str[:200]}...")
                    return output_str
                except Exception as e:
                    logger.error(f"Error executing command: {cmd}, error: {e}")
                    if VERBOSE > 0:
                        print(f"[-] Command execution error: {cmd}")
                        print(f"[-]  {e}")
                    raise CommandError(cmd, return_code=1)
        except Exception as e:
            logger.error(f"Unhandled exception while executing command: {cmd}, error: {str(e)}")
            if VERBOSE > 0:
                print(f"[-] Unhandled exception: {str(e)}")
            raise

    def run_commands(self, cmd_list, VERBOSE=0, DEBUG=False):
        """
        Executes a list of commands with error handling.
        
        Args:
            cmd_list: List of commands to execute
            VERBOSE: Verbosity level (0-2)
            DEBUG: Debug flag
            
        Returns:
            List of command execution results
        """
        results = []
        errors = []
        
        for i, cmd in enumerate(cmd_list):
            try:
                result = self.run_command(cmd, VERBOSE=VERBOSE, DEBUG=DEBUG)
                results.append(result)
            except CommandError as e:
                logger.error(f"Error command{i+1}/{len(cmd_list)}: {e}")
                errors.append(e)
                if VERBOSE > 0:
                    print(f"[!] Command {i+1}/{len(cmd_list)} error: {cmd}")
        
        if errors and VERBOSE > 0:
            print(f"[!] {len(errors)}  {len(cmd_list)} errors")
            
        return results

    def demand_input(self, prompt):
        """
        Args:
            prompt: Prompt for input
            
        Returns:
            User entered string
        """
        response = ""
        while response == "":
            try:
                response = input(prompt).strip()
            except KeyboardInterrupt:
                print("\n[!] Operation interrupted by user")
                sys.exit(1)
            except EOFError:
                print("\n[!] Unexpected end of input")
                sys.exit(1)
        return response

    def root_check(self, debug=False):

        try:
            # Linux check
            if debug:
                print(f'UID: {os.getuid()}')
            if os.getuid() != 0:
                logger.error("Program must be run with root privileges")
                print("[-] Program MUST be run as sudo or root!\nUsage: sudo firewall <options>")
                exit(1)
        except AttributeError:
            # Windows check - use ctypes to check administrator privileges
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[-] Program MUST be run as Administrator in Windows!")
                exit(1)
        
        logger.info("Administrator rights check completed successfully")
        return

    def get_rhel_eth_ifaces(self):
        try:
            if platform.system().lower() == 'windows':
                # For Windows use netsh
                output = self.run_command("powershell.exe -Command \"Get-NetAdapter | Select-Object -ExpandProperty Name\"")
                return [iface.strip() for iface in output.split('\n') if iface.strip()]
            else:
                output = self.run_command("nmcli d | cut -d' ' -f 1")
                return [iface for iface in output.split('\n')[1:] if iface != '']
        except Exception as e:
            return []
    
    def get_config_whiptail(self, DEBUG=False):
        from firewall.base.validation import Validation
        validator = Validation()
        whip = Whiptail(title="Firewall Wizard")

        all_ifaces = self.get_rhel_eth_ifaces()
        if not all_ifaces:
            exit(1)
            
        iface = whip.radiolist('Ethernet interface (press <space> to select): ', items=all_ifaces)[0]

        local_config_fields = [
            ('rh_host', 'RedHat hostname', 1, 1, [validator.hostname_check]),
            ('rh_ipaddr', 'RedHat IP Address', 1, 1, [validator.ip_validator]),
            ('netmask', 'Network Mask', 1, 1, [validator.ip_validator]),
            ('gateway_addr', 'Gateway Address', 1, 1, [validator.ip_validator]),
            ('dns', 'DNS Address (optional)', 0, 1, [validator.ip_validator]),
            ('rh_mac', 'MAC Address (optional, enter * for random)', 0, 1, [validator.mac_check])
        ]

        firewall_config_fields = [
            ('target_range', 'Target range (/32 for single host, enter blank when finished)', 0, 100, [validator.network_validator]),
            ('trusted_range', 'Trusted range (/32 for single host, enter blank when finished)', 0, 100, [validator.network_validator]),
            ('nostrike', 'No-strike range (enter blank when finished)', 0, 100, [validator.network_validator])
        ]

        if DEBUG:
            print("Getting config via whiptail")


        config_builder = []
        config_builder.append('[local_config]\n')
        config_builder.append('iface='+iface+'\n')
        for (field_name, friendly_name, min_entries, max_entries, validators) in local_config_fields:
            for x in range(1, max_entries+1):
                mandatory = True
                if x > min_entries:
                    mandatory = False
                user_input = self.demand_whiptail_input(whip, friendly_name, validators, mandatory)
                if user_input == '':
                    break
                config_builder.append(field_name + '=' + user_input + '\n')

        config_builder.append('\n[firewall_config]\n')
        for (field_name, friendly_name, min_entries, max_entries, validators) in firewall_config_fields:
            for x in range(1, max_entries+1):
                mandatory = True
                if x > min_entries:
                    mandatory = False
                user_input = self.demand_whiptail_input(whip, friendly_name, validators, mandatory)
                if user_input == '':
                    break
                config_builder.append(field_name + '=' + user_input + '\n')

        error_input = ''
        while True:
            msg = error_input + "Enter a filename to output config: "
            try:
                config_filename = self.get_whiptail_input(whip, msg)
                with open(config_filename, 'w') as config_file:
                    config_file.writelines(config_builder)
                break
            except IOError:
                error_input = "Invalid filename.\n\n"
                logger.error(f"Error writing to file: {config_filename}")
                continue

        config_text = ''.join(config_builder)

        if whip.confirm("Would you like to view your config?", default='yes'):
            whip.alert_large(config_text, height=30)

        whip.set_title("Firewall: " + config_filename)
        if whip.confirm("Would you like to execute firewall with this config now?", default='no'):
            self.run_command('firewall -c ' + config_filename, VERBOSE=2)
            logger.info(f"Configuration application command started: firewall -c {config_filename}")

        # escape all other firewall function for this instance
        exit()

    def get_whiptail_input(self, whip, msg):
        return whip.prompt(msg)

    def demand_whiptail_input(self, whip, msg, validator_callbacks, mandatory=True):

        user_input = None
        error_input = ''
        while True:
            user_input = whip.prompt(error_input + msg)
            if user_input.strip() == '' and mandatory == False:
                return ''
            for callback in validator_callbacks:
                if callback(user_input):
                    return user_input
            error_input = "Your entry was invalid.\n\n"
        return None


class Bcolors:
    HEADERS = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
