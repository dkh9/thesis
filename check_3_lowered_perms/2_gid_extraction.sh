#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage: gid_extraction.sh <path to grep> <output.json>"
    exit 1
fi

path_to_grep=$1
output_json=$2

file_list_xml=$(grep -rni "group gid" "$path_to_grep" | cut -d: -f1 | grep -E '\.xml$' | sort -u)

echo "Processing the following XML files:"
printf "%s\n" "$file_list_xml"
echo

# Feed each XML file to the updated Python script
while IFS= read -r xml_file; do
    python3 2_gid_mapping.py "$xml_file" "$output_json"
done <<< "$file_list_xml"