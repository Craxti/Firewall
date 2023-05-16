import argparse


def process_packet(source_ip, destination_ip):
    print(f"Source IP: {source_ip}")
    print(f"Destination IP: {destination_ip}")


parser = argparse.ArgumentParser(description='Firewall Command Line Interface')

parser.add_argument('source_ip', type=str, help='Source IP address')
parser.add_argument('destination_ip', type=str, help='Destination IP address')

args = parser.parse_args()

process_packet(args.source_ip, args.destination_ip)
