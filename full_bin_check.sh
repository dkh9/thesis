#!/bin/bash

if [ $# -lt 3 ]; then
    echo "Usage: full_bin_check.sh <fw1> <fw2> <diffname>"
    exit 1
fi

fw1=$1
fw2=$2
diffname=$3

echo "Unpacking apex...."
./unpack_apexes.sh $fw1
./unpack_apexes.sh $fw2

echo "Diffing, getting the stat..."
git diff --no-index --numstat $fw1 $fw2 > "check_2_bins_libs/${diffname}"

echo "Getting libs and bins..."
check_2_bins_libs/generate_rc_bins_libs.sh $fw2 check_2_bins_libs/intermediate_files/rc_bins.txt check_2_bins_libs/intermediate_files/rc_bins.json check_2_bins_libs/intermediate_files/rc_libs.json 

echo "Calling json dumper..."
python3 json_dumper.py "check_2_bins_libs/${diffname}" "check_2_bins_libs/${diffname}.json" check_2_bins_libs/intermediate_files/rc_bins.json check_2_bins_libs/intermediate_files/rc_libs.json  check_2_bins_libs/intermediate_files/unsorted_bin_digest.json check_2_bins_libs/intermediate_files/unsorted_apk_digest.json check_2_bins_libs/sepolicy_digest.json