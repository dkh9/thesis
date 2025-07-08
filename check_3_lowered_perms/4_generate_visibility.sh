#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "Usage: 4_generate_visibility.sh <path to grep>"
    exit 1
fi

path_to_grep=$1
visibility_extractor="./4_get_visibility.sh"

tmpfile=$(mktemp)

# Extract visibility info from each APK
find "$path_to_grep" -iname '*.apk' | while read -r apk; do
  echo "### $apk" >> "$tmpfile"
  $visibility_extractor "$apk" >> "$tmpfile"
done

# Python script to convert to JSON
python3 - <<EOF
import json
from collections import defaultdict

result = defaultdict(list)
current_apk = None

with open("$tmpfile") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        if line.startswith("###"):
            current_apk = line[4:]
        elif current_apk:
            parts = line.split(",", 3)
            if len(parts) != 4:
                continue
            component_type, name, exported, permission = parts
            result[current_apk].append({
                "type": component_type,
                "name": name,
                "exported": exported,
                "permission": permission
            })

print(json.dumps(result, indent=2))
EOF

rm "$tmpfile"