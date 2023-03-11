import texttable
import sys
import json

# Parse args
args = sys.argv[1:]

# Json file
input_json = args[0]

# Output file
output_file = args[1]

# Open json input file
with open(input_json, "r") as in_file:
    data = json.load(in_file)

# Table 1: All info
overview_table = texttable.Texttable()


overview_table.set_cols_width([7,10,5,5,5,15,15,5,10,5,10])


overview_table.header(["domain","geo locations",
                        "hsts","http_server","insecure_http",
                        "ipv4_addresses","ipv6_addresses",
                        "redirect_to_https",
                        "rtt_range","scan_time","tls_versions"])

for domain in data.keys():
    overview_table.add_row([domain, ", ".join(data[domain]["geo_locations"]),
                            str(data[domain]["hsts"]), data[domain]["http_server"],
                            str(data[domain]["insecure_http"]), ", ".join(data[domain]["ipv4_addresses"]),
                            ", ".join(data[domain]["ipv6_addresses"]), str(data[domain]["redirect_to_https"]),
                            data[domain]["rtt_range"], data[domain]["scan_time"],
                            ", ".join(data[domain]["tls_versions"])])
    

# Table 2: RTT ranges, sorted from fastest to slowest
rtt_table = texttable.Texttable()

rtt_list = []

for domain in data.keys():
    rtt_list.append([domain, data[domain]["rtt_range"]])

rtt_list.sort(key= lambda x: x[1][0])


rtt_table.header(["domain","Lower bound","Upper bound"])

for dom in rtt_list:
    rtt_table.add_row([dom[0],dom[1][0], dom[1][1]])


# Table 3: Number of occurences of each root ca, sorted most popular to least

ca_count = {}

for domain in data.keys():
    if "root_ca" in data[domain].keys():
        if data[domain]["root_ca"] in ca_count.keys():
            ca_count[data[domain]["root_ca"]] += 1
        else:
            ca_count[data[domain]["root_ca"]] = 1

ca_list = list(ca_count.items())

ca_list.sort(key= lambda x: x[1], reverse=True)

ca_table = texttable.Texttable()

ca_table.header(["root ca", "count"])

for ca in ca_list:
    ca_table.add_row([ca[0],ca[1]])

# Table 4: Number of occurences of each web server, sorted most popular to least

http_server_count = {}

for domain in data.keys():
    if data[domain]["http_server"] in http_server_count.keys():
        http_server_count[data[domain]["http_server"]] += 1
    else:
        http_server_count[data[domain]["http_server"]] = 1

http_list = list(http_server_count.items())

http_list.sort(key= lambda x: x[1], reverse=True)

http_table = texttable.Texttable()

http_table.header(["http server", "count"])

for http in http_list:
    http_table.add_row([http[0],http[1]])


# Table 5: Percentage of scanned domains supporting various metrics

num_domains = len(data.keys())

percent_table = texttable.Texttable()

percent_table.header(["Functionality", "Percent supporting"])

# insecure count
insecure_count = 0

# redirect_count
redirect_count = 0

# hsts
hsts_count = 0

# IPv6 
ipv6_count = 0

tls_count = {"SSLv2": 0,
            "SSLv3": 0,
            "TLSv1.0": 0,
            "TLSv1.1": 0,
            "TLSv1.2": 0,
            "TLSv1.3": 0}

# Get data for tls_versions
for domain in data.keys():

    # Get data for tls_versions
    tls_data = data[domain]["tls_versions"]


    for v in tls_count.keys():

        if v in tls_data:
            tls_count[v] += 1

    
    # insecure
    if data[domain]["insecure_http"]:
        insecure_count += 1

    # redirect
    if data[domain]["redirect_to_https"]:
        redirect_count += 1

    # hsts
    if data[domain]["hsts"]:
        hsts_count += 1

    # IPv6

    if data[domain]["ipv6_addresses"]:
        ipv6_count += 1


for v in tls_count.keys():  
    
    percent_table.add_row([v, str(float(tls_count[v]/num_domains) * 100) + "%"])

percent_table.add_row(["insecure_http", str(float(insecure_count/num_domains) * 100) + "%"])
percent_table.add_row(["redirect_to_https", str(float(redirect_count/num_domains) * 100) + "%"])
percent_table.add_row(["hsts", str(float(hsts_count/num_domains) * 100) + "%"])
percent_table.add_row(["ipv6_addresses", str(float(ipv6_count/num_domains) * 100) + "%"])

# Output to output_file
with open(output_file, "w") as out_file:
    out_file.write("Overview table:\n")
    out_file.write(overview_table.draw())
    out_file.write("\n\nRTT Ranges:\n")
    out_file.write(rtt_table.draw())
    out_file.write("\n\nRoot certificate authority occurences:\n")
    out_file.write(ca_table.draw())
    out_file.write("\n\nWeb server occurences:\n")
    out_file.write(http_table.draw())
    out_file.write("\n\nFunctionality support percentages:\n")
    out_file.write(percent_table.draw())

