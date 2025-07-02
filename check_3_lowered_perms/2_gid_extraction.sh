#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "Usage: gid_extraction.sh <path to grep>"
    exit 1
fi

path_to_grep=$1


file_list=$(grep -rni "group gid" $path_to_grep | cut -d: -f1 | sort -u)
file_list_xml=$(grep -rni "group gid" $path_to_grep | cut -d: -f1 | grep -E '\.xml$' | sort -u)

# Echo the list
echo "$file_list"
echo
echo "File list xml:"
echo $file_list_xml

printf "%s\n" "$file_list_xml" | python3 2_gid_mapping.py