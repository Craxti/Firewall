import argparse
from src.action import ExecuteScriptAction


def process_packet(source_ip, destination_ip):
    print(f"Source IP: {source_ip}")
    print(f"Destination IP: {destination_ip}")


parser = argparse.ArgumentParser(description='Firewall Command Line Interface')

parser.add_argument('source_ip', type=str, help='Source IP address')
parser.add_argument('destination_ip', type=str, help='Destination IP address')

# python main.py --script-path path/to/script.py --arguments arg1 arg2 arg3
parser.add_argument('--script-path', help='Path to the script')
parser.add_argument('--arguments', nargs='*', help='Arguments for the script')

args = parser.parse_args()

process_packet(args.source_ip, args.destination_ip)
execute_action = ExecuteScriptAction(script_path=args.script_path, arguments=args.arguments)
