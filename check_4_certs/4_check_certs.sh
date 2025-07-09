#!/bin/bash

RESULTS_DIR="analysis_results"
CERT_DIFF_JSON="cert_diff.json"

if [ $# -eq 0 ]
  then
    echo "Usage: compare.sh <extracted fs 1> <extracted fs 2>"
    exit 1
fi
fw1=$1
fw2=$2

echo "fw1: $fw1"
echo "fw2: $fw2"

mkdir "${RESULTS_DIR}"
echo '{"added": [], "removed": [], "modified": []}' > "${RESULTS_DIR}/${CERT_DIFF_JSON}"

dump_json_array_entry() {
  local key="$1"
  local json_entry="$2"

  tmpfile=$(mktemp)
  jq --argjson entry "$json_entry" --arg key "$key" '.[$key] += [$entry]' "${RESULTS_DIR}/${CERT_DIFF_JSON}" > "$tmpfile" && mv "$tmpfile" "${RESULTS_DIR}/${CERT_DIFF_JSON}"
}

dump_modified_entry() {
  local file1="$1"
  local file2="$2"

  info1=$(./cert_info.py "$file1")
  info2=$(./cert_info.py "$file2")

  json_entry=$(jq -n \
    --arg path1 "$file1" \
    --arg path2 "$file2" \
    --argjson cert1 "$info1" \
    --argjson cert2 "$info2" \
    '{cert1: $cert1, cert2: $cert2, path1: $path1, path2: $path2}')

  dump_json_array_entry "modified" "$json_entry"
}

dump_added_entry() {
  local file="$1"
  local info=$(./cert_info.py "$file")

  json_entry=$(jq -n --arg path "$file" --argjson cert "$info" '{path: $path, cert: $cert}')
  dump_json_array_entry "added" "$json_entry"
}

dump_removed_entry() {
  local file="$1"
  local info=$(./cert_info.py "$file")

  json_entry=$(jq -n --arg path "$file" --argjson cert "$info" '{path: $path, cert: $cert}')
  dump_json_array_entry "removed" "$json_entry"
}



check_single_path() {
  local result="$1"

  if [ -z "$result" ]; then
    echo "Error: No matching file found."
    return 1
  fi

  local count
  count=$(echo "$result" | wc -l)

  if [ "$count" -ne 1 ]; then
    echo "Error: Multiple matching files found."
    return 2
  fi

  return 0
}

#

certificate_analysis() {
  
  declare -A certs_dict_1
  declare -A certs_dict_2

  get_certs_paths() {
    local extracted_dir=$1
    local certs_ref=$2

    user_parts=$extracted_dir

    declare -n certs_dests=$certs_ref

    system_certs=$(find "${user_parts}/system" -iname cacerts)
    echo "-- Checking system certs"
    check_single_path "$system_certs"
    ret=$?
    if [ "$ret" -eq 0 ]; then
      echo "System location found"
      certs_dests["system"]=$system_certs
    elif [ "$ret" -eq 1 ]; then
      echo "cacerts in ${user_parts}/system not found"
    else
      echo "Unexpected amount of cacerts locations in ${user_parts}/system"
    fi


    vendor_certs=$(find "${user_parts}/vendor" -iname cacerts)
    echo "-- Checking vendor certs"
    check_single_path "$vendor_certs"
    ret=$?
    if [ "$ret" -eq 0 ]; then
      echo "Vendor location found"
      certs_dests["vendor"]=$vendor_certs
    elif [ "$ret" -eq 1 ]; then
      echo "cacerts in ${user_parts}/vendor not found"
    else
      echo "Unexpected amount of cacerts locations in ${user_parts}/vendor"
    fi
  }


  echo -e "\n--------------Comparing certificates--------------"
  echo "FW1"
  get_certs_paths $fw1 certs_dict_1
  echo -e "\n"
  echo "FW2"
  get_certs_paths $fw2 certs_dict_2
  echo -e "\n"
  
  has_1_system=false
  has_2_system=false
  
  for key in "system" "vendor"; do
      echo "Checking key: $key"
  
      has_1=false
      has_2=false
  
      if [ -v certs_dict_1["$key"] ]; then
          has_1=true
          path_1=${certs_dict_1["$key"]}
      fi
  
      if [ -v certs_dict_2["$key"] ]; then
          has_2=true
          path_2=${certs_dict_2["$key"]}
      fi
  
      if $has_1 && $has_2; then
          echo "Both vendors have '$key' key, running diff:"
          mapfile -t diff_output < <( diff -rq "$path_1" "$path_2")
          echo "Diff output: $diff_output"
          echo "Path1 : $path_1"
          echo "Path2 : $path_2"

          for line in "${diff_output[@]}"; do
            if [[ "$line" =~ ^Only\ in\ ([^:]+):\ (.+)$ ]]; then
              dir="${BASH_REMATCH[1]}"
              file="${BASH_REMATCH[2]}"

              echo "Only in!"
              echo "${dir}/${file}"
              #----dump to JSON here

              if [[ "$(realpath "$dir")" == "$(realpath "$path_1")" ]]; then
                dump_removed_entry "${dir}/${file}"
              fi
              if [[ "$(realpath "$dir")" == "$(realpath "$path_2")" ]]; then
                dump_added_entry "${dir}/${file}"
              fi


            elif [[ "$line" =~ ^Files\ (.+)\ and\ (.+)\ differ$ ]]; then
              file1="${BASH_REMATCH[1]}"
              file2="${BASH_REMATCH[2]}"

              echo "File 1: $file1"
              echo "File 2: $file2"

              
              #output=$(./cert_equivalence.py "$file1" "$file2")

              #if [[ $? -eq 1 ]]; then
              #if [[ "$output" == "1" ]]; then
              if ./cert_equivalence.py "$file1" "$file2"; then
                echo "True comparison result: different!"

                #-----------dump to JSON here
                dump_modified_entry "$file1" "$file2"

              else
                echo "True comparison result: same!"
              fi
              #echo -e "\n\n"
            fi
          done #<---- HERE

      elif $has_1; then
          echo "'$key' key exists only in VENDOR 1: $path_1"
      elif $has_2; then
          echo "'$key' key exists only in VENDOR 2: $path_2"
      else
          echo "'$key' key missing in both VENDOR 1 and VENDOR 2"
      fi
  
      echo
  done
}


certificate_analysis