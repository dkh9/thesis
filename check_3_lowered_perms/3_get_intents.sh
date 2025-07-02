#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "Usage: get_intents.sh <path to grep>"
    exit 1
fi

path_to_grep=$1

find $path_to_grep -iname '*.apk' | while read apk; do
  echo "== $apk =="
  aapt2 dump xmltree "$apk" --file AndroidManifest.xml | awk '
    $1 == "E:" && $2 == "action" { in_action=1; next }
    in_action && $1 == "A:" && $2 ~ /name/ {
      match($0, /"([^"]+)"/, arr)
      print arr[1]
      in_action=0
    }
  '
done