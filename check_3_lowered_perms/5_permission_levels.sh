#!/bin/bash

if [ $# -eq 0 ]; then
  echo "Usage: 5_permission_levels.sh <path to grep> <outfile.json>"
  exit 1
fi

APKANALYZER=/opt/android-sdk/cmdline-tools/latest/bin/apkanalyzer

path_to_grep=$1
outfile=$2
#echo "$path_to_grep"

find "$path_to_grep" -iname '*.apk' | while read -r apk; do
  #echo "Processing $apk"

  manifest=$("$APKANALYZER" manifest print "$apk" 2>/dev/null)

  if [ -z "$manifest" ]; then
    echo "Skipping $apk: no manifest found"
    continue
  fi

  echo "$manifest" | python3 5_parse_manifest.py --apk "$apk" --outfile "$outfile"
done
