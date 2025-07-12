#!/bin/bash

if [ $# -lt 3 ]; then
    echo "Usage: generate_rc_bins_libs.sh <rc_dir> <list of bins name> <list of bins json name> <lib json output file>"
    exit 1
fi

rc_dir=$1
bin_list=$2
bin_json=$3
lib_json_map=$4

python3 find_init_binaries.py $rc_dir $bin_list $bin_json
python3 elf_libs.py $bin_list > $lib_json_map