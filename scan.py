import time
import sys
import json
import subprocess

# Parse arguments
args = sys.argv[1:]

# Input File
input_file = args[0]

# Output File
output_file = args[1]

# Output JSON
output = {}

# Open the file
with open(input_file, "r") as in_file:
    for domain in in_file:

        # Print which domain
        print(f"\n************************************\n\nRunning scanners on {domain}\n************************************")

        # Remove "\n" from domain
        domain = domain.strip()

        # A.) SCAN TIME
        output[domain] = {"scan_time": time.time()}
        print("\nPart A (scan_time) successful.\nStarting part B (ipv4_addresses)...\n")

        # B.) IPv4 Addresses
        resolvers = ['208.67.222.222', '1.1.1.1', '8.8.8.8', '8.26.56.26',
                     '9.9.9.9', '64.6.65.6', '91.239.100.100', '185.228.168.168',
                     '77.88.8.7', '156.154.70.1', '198.101.242.72', '176.103.130.130']

        # Function to scan IP address of different types (IPv4 and IPv6)
        def ip_scan(query_type):
            ip_addresses = []
            for resolver in resolvers:
                try:
                    result = subprocess.check_output(["nslookup", f"-type={query_type}", domain, resolver],
                                                    timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                    lines = result.strip().split('\n')
                    for line in lines:
                        if 'Address:' in line:
                            ip_addresses.append(line.split()[-1])
                    print(f"{domain} worked with resolver {resolver}", file=sys.stdout)
                except subprocess.TimeoutExpired as e:
                    print(f"Timeout error while trying to resolve {domain} with resolver {resolver}", file=sys.stderr)
                except subprocess.CalledProcessError as e:
                    print(f"Error while trying to resolve {domain} with resolver {resolver}", file=sys.stderr)
            if ip_addresses:
                if query_type == "A":
                    output[domain]["ipv4_addresses"] = ip_addresses
                elif query_type == "AAAA":
                    output[domain]["ipv6_addresses"] = ip_addresses
                else:
                    print(f"Incorrect DNS record type", file=sys.stderr)
                    sys.exit(1)

        # Scan for IPv4 addresses ()
        ip_scan('A')
        print("\nPart B (ipv4_addresses) successful.\nStarting part C (ipv6_addresses)...\n")

        # C.) IPv6 Addresses
        ip_scan('AAAA')
        print("\nPart C (ipv6_addresses) successful.\nStarting part D (http_server)...\n")

# Output to JSON
with open(output_file, "w") as out_file:
    json.dump(output, out_file, sort_keys=True, indent=4)
