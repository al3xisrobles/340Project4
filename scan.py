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
with open(input_file, "rw") as in_file:
    for domain in in_file:

        # A.) SCAN TIME
        output[domain] = {"scan_time": time.time()}

# Output to JSON
with open(output_file, "w") as out_file:
    json.dump(output, out_file, sort_keys=True, indent=4)
