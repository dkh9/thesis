#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "Usage: get_visibility.sh <apk>"
    exit 1
fi

apk=$1

aapt2 dump xmltree "$apk" --file AndroidManifest.xml | awk '
  BEGIN {
    component=""; name=""; exported=""; permission=""; in_intent=0
  }
  $1=="E:" && ($2=="activity" || $2=="service" || $2=="receiver" || $2=="provider") {
    # If previous component is not empty, output it
    if (component != "" && name != "") {
      if (exported == "") exported = (in_intent==1) ? "true" : "false"
      printf("%s,%s,%s,%s\n", component, name, exported, permission)
    }
    # Start new component
    component=$2; name=""; exported=""; permission=""; in_intent=0
  }
  $1=="A:" && /name/ {
    match($0, /"([^"]+)"/, arr)
    name = arr[1]
  }
  $1=="A:" && /exported/ {
    match($0, /"([^"]+)"/, arr)
    exported = arr[1]
  }
  $1=="A:" && /permission/ {
    match($0, /"([^"]+)"/, arr)
    permission = arr[1]
  }
  $1=="E:" && $2=="intent-filter" {
    in_intent=1
  }
  END {
    if (component != "" && name != "") {
      if (exported == "") exported = (in_intent==1) ? "true" : "false"
      printf("%s,%s,%s,%s\n", component, name, exported, permission)
    }
  }
'
