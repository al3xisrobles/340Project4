import time
import sys
import json
import subprocess
import requests
import socket
import urllib.parse
import maxminddb

# Parse arguments
args = sys.argv[1:]

# Input File
input_file = args[0]

# Output File
output_file = args[1]

# Output JSON
output = {}

####  HELPER FUNCTIONS  ####

# Function to scan IP address of different types (IPv4 and IPv6) with different DNS resolvers
resolvers = ['208.67.222.222', '1.1.1.1', '8.8.8.8', '8.26.56.26',
                     '9.9.9.9', '64.6.65.6', '91.239.100.100', '185.228.168.168',
                     '77.88.8.7', '156.154.70.1', '198.101.242.72', '176.103.130.130']
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

import socket

def measure_rtt(ip_address):
    ports = [80, 22, 443]
    for port in ports:
        print(f"Testing RTT to {ip_address}:{port}")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                start_time = time.time()
                s.connect((ip_address, port))
                s.sendall(b"\x1dclose\x0d")
                s.recv(1024)
                end_time = time.time()
                rtt = (end_time - start_time) * 1000
                return rtt
        except Exception:
            pass
    return None


# Open the file
with open(input_file, "r") as in_file:
    for domain in in_file:

        # Print which domain
        print(f"************************************\n\nRunning scanners on {domain}\n************************************")

        # Remove "\n" from domain
        domain = domain.strip()

        # A.) Scan Time
        output[domain] = {"scan_time": time.time()}
        print("\nPart A (scan_time) successful.\nStarting part B (ipv4_addresses)...\n")

        # B.) IPv4 Addresses
        ip_scan('A')
        print("\nPart B (ipv4_addresses) successful.\nStarting part C (ipv6_addresses)...\n")

        # C.) IPv6 Addresses
        ip_scan('AAAA')
        print("\nPart C (ipv6_addresses) successful.\nStarting part D (http_server)...\n")

        # D.) HTTP Server
        if "ipv4_addresses" in output[domain]:

            # Pick any IP
            ip_address = output[domain]["ipv4_addresses"][0]

            try:
                response = requests.head(f"http://{ip_address}", timeout=2)
                server_header = response.headers.get("Server")
                output[domain]["http_server"] = server_header or None
                print(f"{domain} has an HTTP server of {server_header}", file=sys.stdout)
            except requests.exceptions.RequestException as e:
                print(f"Error while trying to get HTTP server for {domain} with IP address {ip_address}: {e}", file=sys.stderr)
                output[domain]["http_server"] = None
        print("\nPart D (http_server) successful.\nStarting part E (insecure_http)...\n")

        # E.) Insecure HTTP
        url = f"http://{domain}:80"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                output[domain]["insecure_http"] = True
                print(f"{domain} allows unsecure HTTP requests")
            else:
                output[domain]["insecure_http"] = False
                print(f"{domain} does not allow unsecure HTTP requests")
        except Exception as e:
            # Port is not open or some error occurred
            output[domain]["insecure_http"] = False
            print(f"{domain} did not work with IP address {ip_address}: {e}", file=sys.stderr)
        print("\nPart E (insecure_http) successful.\nStarting part F (redirect_to_https)...\n")

        # F.) Redirect to HTTPS
        if "ipv4_addresses" in output[domain]:
            ip_address = output[domain]["ipv4_addresses"][0].split("#")[0]
            try:

                # Check if port 80 is open
                with socket.create_connection((ip_address, 80), timeout=2) as sock:
                    # Send HTTP request
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\n\r\n")
                    response = sock.recv(1024).decode()
                    if "HTTP/1.1 301" in response or "HTTP/1.1 302" in response:
                        output[domain]["redirect_to_https"] = True
                    else:
                        output[domain]["redirect_to_https"] = False
                    print(f"{domain} worked with IP address {ip_address}", file=sys.stdout)

            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                # Port is not open or some error occurred
                print(f"{domain} did not work with IP address {ip_address}: {e}", file=sys.stderr)
        print("\nPart F (redirect_to_https) successful.\nStarting part G (hsts)...\n")

        # G.) HTTP Strict Transport Security (hsts)
        url = domain
        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme:
            url = "https://" + url

        try:
            response = requests.get(url, timeout=5)
            response_headers = response.headers
            if "strict-transport-security" in response_headers:
                output[domain]["hsts"] = True
                print('Found strict transport security header')
            else:
                output[domain]["hsts"] = False
                print('No strict transport security header')
        except requests.exceptions.RequestException as e:
            print(f"Error while trying to check whether HSTS has been enabled for {url}: {e}", file=sys.stderr)
        print("\nPart G (hsts) successful.\nStarting part H (tls_versions)...\n")

        # H.) TLS Versions
        tls_versions_out = []
        version_options = {"ssl2": "SSLv2",
                           "ssl3": "SSLv3",
                           "tls1": "TLSv1.0",
                           "tls1_1": "TLSv1.1",
                           "tls1_2": "TLSv1.2",
                           "tls1_3": "TLSv1.3"}
        for version in version_options.keys():
            try:
                res = subprocess.check_output(['echo', '|', 'openssl', 's_client', f'-{version}', '-connect', f'{domain}:443'], stderr=subprocess.STDOUT, timeout=2, input=b'')
                tls_versions_out.append(version_options[version])
                output[domain]["tls_versions"] = tls_versions_out
            except Exception as e:
                print(f"Error while trying to check TLS versions for {domain}: {e}")
        print(f"{domain} allows TLS versions: {tls_versions_out}")
        print("\nPart H (tls_versions) successful.\nStarting part I (root_ca)...\n")

        # I.) Root CA
        try:
            root_ca = subprocess.check_output(f"echo | openssl s_client -connect {domain}:443 -showcerts | awk '/Root CA/,/END CERTIFICATE/' | openssl x509 -noout -issuer | sed -n 's/.*O=//p'", shell=True, timeout=2, encoding="utf-8").strip()

            # Remove everything but the org
            if '/' in root_ca:
                root_ca = root_ca.split('/')[0]

            # Root CA might be null
            if root_ca:
                output[domain]["root_ca"] = root_ca
        except Exception as e:
            print(f"Error while trying to fetch root CA for {domain}: {e}")
        print("\nPart I (root_ca) successful.\nStarting part J (rdns_names)...\n")

        # J.) RDNS Names
        ip_address = output[domain]["ipv4_addresses"][0].split("#")[0]
        try:
            ret = subprocess.check_output(['dig', '-x', ip_address], timeout=2, universal_newlines=True)
            rdns_names = [line.split()[-1][:-1] for line in ret.splitlines() if 'PTR' in line and ';' not in line]
            print(f"Found RDNS names:", rdns_names)
        except (socket.herror, socket.gaierror) as e:
            print(f"Error while trying to fetch reverse DNS names for {domain}: {e}")
            rdns_names = []
        output[domain]["rdns_names"] = rdns_names
        print("\nPart J (rdns_names) successful.\nStarting part K (rtt_range)...\n")

        # K.) RTT Range
        ip_list = output[domain]["ipv4_addresses"]
        ip_list = [ip.split("#")[0] for ip in ip_list]

        rtts = []
        for ip_address in ip_list:
            rtt = measure_rtt(ip_address)
            if rtt is not None:
                rtts.append(rtt)
        if len(rtts) > 0:
            output[domain]['rtt_range'] = [min(rtts), max(rtts)]
        else:
            output[domain]['rtt_range'] = None
        print("\nPart K (rtt_range) successful.\nStarting part L (geo_locations)...\n")

        # L.) Geo Locations
        locations = set()
        with maxminddb.open_database('GeoLite2-City.mmdb') as db:
            for ip_address in ip_list:
                try:
                    response = db.get(ip_address)
                    city = response['city']['names']['en']
                    province = response['subdivisions'][0]['names']['en']
                    country = response['country']['names']['en']
                    location = f"{city}, {province}, {country}"
                    locations.add(location)
                except Exception as e:
                    pass
        print("Found locations:", str(locations))
        output[domain]["geo_locations"] = list(locations)
        print("\nPart L (geo_locations) successful.\n")

# Output to JSON
with open(output_file, "w") as out_file:
    json.dump(output, out_file, sort_keys=True, indent=4)
