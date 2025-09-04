#!/usr/bin/env python3
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
import json
import os

if len(sys.argv) != 3:
    print("Usage: 2_gid_mapping.py <input_xml_file> <output_json_file>")
    sys.exit(1)

input_file = sys.argv[1]
output_json = sys.argv[2]

# Final map: gid -> list of permissions
gid_map = defaultdict(set)  # Use set to avoid duplicates

# Load existing file if present
if os.path.exists(output_json):
    try:
        with open(output_json, "r") as f:
            existing = json.load(f)
            for gid, perms in existing.items():
                gid_map[gid].update(perms)
    except Exception as e:
        print(f"Error reading existing JSON file {output_json}: {e}", file=sys.stderr)

# Parse input XML
try:
    tree = ET.parse(input_file)
    root = tree.getroot()

    for perm in root.findall('permission'):
        perm_name = perm.get('name')
        if perm_name is None:
            continue

        for group in perm.findall('group'):
            gid = group.get('gid')
            if gid:
                gid_map[gid].add(perm_name)

except Exception as e:
    print(f"Error parsing {input_file}: {e}", file=sys.stderr)

# Print results (for debug or visual check)
for gid, permissions in gid_map.items():
    print(f"GID: {gid}")
    for perm in sorted(permissions):
        print(f"  - Permission: {perm}")

# Write final merged map to output
result = {gid: sorted(list(perms)) for gid, perms in gid_map.items()}

with open(output_json, "w") as f:
    json.dump(result, f, indent=2)

print(f"\nUpdated GID map written to {output_json}")