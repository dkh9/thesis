#!/bin/bash

if [ $# -lt 3 ]; then
    echo "Usage: generate_rc_bins_libs.sh <rc_dir> <list of bins name> <lib json output file>"
    exit 1
fi

rc_dir=$1
bin_list=$2
json_map=$3

python3 find_init_binaries.py $rc_dir $bin_list
python3 elf_libs.py $bin_list > $json_map