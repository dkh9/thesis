#!/bin/bash

if [ $# -lt 2 ]
  then
    echo "Usage: run_all_checks.sh <path to grep 1> <path to grep 2>"
    exit 1
fi

path_1=$1
path_2=$2

mkdir intermediate_files
mkdir result_digests
------------------check 1: protection level mapping
./1_protection_level_extraction.sh $path_1 intermediate_files/v1_protection_level.jsonl
./1_protection_level_extraction.sh $path_2 intermediate_files/v2_protection_level.jsonl

python3 1_protection_level_digest.py intermediate_files/v1_protection_level.jsonl intermediate_files/v2_protection_level.jsonl result_digests/1_protection_diff_digest.json
echo "Check 1 done"

#------------------check 2: gid mapping

./2_gid_extraction.sh $path_1 intermediate_files/v1_gid_map.json
./2_gid_extraction.sh $path_2 intermediate_files/v2_gid_map.json
python3 2_gid_protection_digest.py intermediate_files/v1_gid_map.json intermediate_files/v2_gid_map.json intermediate_files/v2_protection_level.jsonl result_digests/1_protection_diff_digest.json result_digests/2_gid_digest.json
echo "Check 2 done"

#------------------check 3: broadcasts regressions
./3_protected_broadcasts.sh $path_1 > intermediate_files/v1_broadcasts.txt
./3_get_intents.sh $path_1 > intermediate_files/v1_intents.txt
./3_protected_broadcasts.sh $path_2 > intermediate_files/v2_broadcasts.txt
./3_get_intents.sh $path_2 > intermediate_files/v2_intents.txt

python3 3_check_undeclared_broadcasts.py intermediate_files/v1_broadcasts.txt intermediate_files/v1_intents.txt intermediate_files/v2_broadcasts.txt intermediate_files/v2_intents.txt result_digests/3_undeclared_broadcast_digest.json
echo "Check 3 done"

#------------------check 4: visibility regressions


./4_generate_visibility.sh $path_1 > intermediate_files/v1_visibility.txt
./4_generate_visibility.sh $path_2 > intermediate_files/v2_visibility.txt#

python3 4_visibility_digest.py intermediate_files/v1_visibility.txt intermediate_files/v2_visibility.txt result_digests/4_visibility_digest.json
echo "Check 4 done"
#------------------check 5: components regressions

./5_permission_levels.sh  $path_1 intermediate_files/v1_components.json
./5_permission_levels.sh  $path_2  intermediate_files/v2_components.json

python3 5_component_digest.py intermediate_files/v1_components.json intermediate_files/v2_components.json intermediate_files/v2_protection_level.jsonl result_digests/1_protection_diff_digest.json result_digests/5_component_visibility_digest.json
echo "Check 5 done"