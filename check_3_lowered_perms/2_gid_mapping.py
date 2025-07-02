import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
import json

# Final map: gid -> list of permissions
gid_map = defaultdict(set)  # Use set to avoid duplicates

# Read file paths from stdin
for file_path in sys.stdin:
    file_path = file_path.strip()
    if not file_path:
        continue

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for perm in root.findall('permission'):
            perm_name = perm.get('name')
            if perm_name is None:
                continue  # Skip malformed entries

            for group in perm.findall('group'):
                gid = group.get('gid')
                if gid:
                    gid_map[gid].add(perm_name)

    except Exception as e:
        print(f"Error parsing {file_path}: {e}", file=sys.stderr)

# Print the results
for gid, permissions in gid_map.items():
    print(f"GID: {gid}")
    for perm in sorted(permissions):
        print(f"  - Permission: {perm}")


result = {gid: sorted(list(perms)) for gid, perms in gid_map.items()}
print(json.dumps(result, indent=2))
with open("gid_map.json", "w") as f:
  f.write(json.dumps(result, indent=2))