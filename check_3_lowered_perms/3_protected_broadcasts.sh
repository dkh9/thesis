#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "Usage: protected_broadcasts.sh <path to grep>"
    exit 1
fi

path_to_grep=$1

find $path_to_grep -iname '*.apk' | while read -r apk; do
  echo "### $apk"
  aapt2 dump xmltree "$apk" --file AndroidManifest.xml 2>/dev/null | awk '
    /E: protected-broadcast/ {flag=1; next}
    flag && /A: .*name/ {
      match($0, /"([^"]+)"/, arr)
      print arr[1]
      flag=0
    }
  '
done