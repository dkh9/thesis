#!/bin/bash

if [ $# -lt 2 ]
  then
    echo "Usage: protection_level_extraction.sh <path to grep> <output file>"
    exit 1
fi

path_to_grep=$1
output_file=$2
jar_files=()
apk_files=()
other_files=()

protection_definition_list=() #IMPORTANT TO FILL OUT HERE

echo "The output file is $output_file"
#grep_result=$(grep -rni "<permission name" "$path_to_grep" 2>&1)

grep_result=$(grep -rni "protectionlevel" "$path_to_grep" 2>&1)

#first of all, I want to grep recursively for protection level definitions
echo "Original grep result:"
printf "%s\n" "$grep_result"
echo "-----------------------------"

#get individual filenames and split them into two lists by extension:
while IFS= read -r line; do
  if [[ "$line" =~ ^grep:\ (.*):\ binary\ file\ matches$ ]]; then
    file="${BASH_REMATCH[1]}"
    if [[ "$file" == *.jar ]]; then
      jar_files+=("$file")
    elif [[ "$file" == *.apk ]]; then
      apk_files+=("$file")
    else
      other_files+=("$file")
    fi
  fi
done <<< "$grep_result"

# Output
echo "JAR files:"
for f in "${jar_files[@]}"; do
  echo "$f"
done

echo
echo "APK files:"
for f in "${apk_files[@]}"; do
  echo "$f"
done

echo 
echo "Other files:"
for f in "${other_files[@]}"; do
  echo "$f"
done

echo 
echo "Processing jars"

for elem in "${jar_files[@]}"; do
    # Extract a safe name for the output folders (remove slashes)
    safe_name=$(echo "$elem" | sed 's/\//_/g')

    echo "Processing jar: $elem --> $safe_name"

    jadx -d "protection_levels_jar/${safe_name}_decompiled" "$elem"

    # Grep for protectionLevel and save to variable
    grep_output=$(grep -rni "protectionlevel" "protection_levels_jar/${safe_name}_decompiled")

    extra_info=$(grep -r "protectionLevel" "protection_levels_jar/${safe_name}_decompiled" | sed -n 's/.*android:name="\([^"]*\)".*android:protectionLevel="\([^"]*\)".*/\1 \2/p')
    echo "$extra_info" >> "protection_level_digest.txt"
    printf "%s\n" "$extra_info" | python3 -c "
import sys, json
output_path = sys.argv[1]
for line in sys.stdin:
    parts = line.strip().split(None, 1)
    if len(parts) == 2:
        data = {\"permission_name\": parts[0], \"protection_level\": parts[1]}
        with open(output_path, 'a') as f:
            f.write(json.dumps(data) + '\n')
" "$output_file"

    # Print summary to terminal
    echo "=== permission matches in $elem ==="
    #echo "$grep_output"
    echo
done

for elem in "${apk_files[@]}"; do
    safe_name=$(echo "$elem" | sed 's/\//_/g')

    echo "Processing apk: $elem --> $safe_name"

    # Decode using apktool
    apktool d -o "protection_levels_apk/${safe_name}.decoded" "$elem"

    # Grep for protectionLevel and save to variable
    grep_output=$(grep -rni "protectionlevel" "protection_levels_apk/${safe_name}.decoded")

    extra_info=$(grep -r "protectionLevel" "protection_levels_apk/${safe_name}.decoded" | sed -n 's/.*android:name="\([^"]*\)".*android:protectionLevel="\([^"]*\)".*/\1 \2/p')
    echo "$extra_info" >> "protection_level_digest.txt"

    printf "%s\n" "$extra_info" | python3 -c "
import sys, json
output_path = sys.argv[1]
for line in sys.stdin:
    parts = line.strip().split(None, 1)
    if len(parts) == 2:
        data = {\"permission_name\": parts[0], \"protection_level\": parts[1]}
        with open(output_path, 'a') as f:
            f.write(json.dumps(data) + '\n')
" "$output_file"

done

rm -rf ./protection_levels_jar 
rm -rf ./protection_levels_apk
rm protection_level_digest.txt