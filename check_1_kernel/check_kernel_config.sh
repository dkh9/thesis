#!/bin/bash

KERNEL_1_ELF="kernel_1.elf"
KERNEL_2_ELF="kernel_2.elf"
CONFIG_1="kernel_1.config"
CONFIG_2="kernel_2.config"
EXTRACT_IKCONFIG_PATH="/home/dasha/thesis/tools/extract-ikconfig"
HARDENING_CHECKER_PATH="/home/dasha/thesis/tools/kernel-hardening-checker/bin/kernel-hardening-checker"
SEC_1="hardening_1.txt"
SEC_2="hardening_2.txt"
KERNEL_DIGEST_FILE="kernel_digest.json"

if [ $# -lt 2 ]; then
    echo "Usage: check_kernel_config.sh <path to kernel 1> <path to kernel 2>"
    exit 1
fi

kernel_1_path=$1
kernel_2_path=$2

vmlinux-to-elf "$kernel_1_path" "$(pwd)/$KERNEL_1_ELF"
vmlinux-to-elf "$kernel_2_path" "$(pwd)/$KERNEL_2_ELF"
"$EXTRACT_IKCONFIG_PATH" "$KERNEL_1_ELF" > "$CONFIG_1"
"$EXTRACT_IKCONFIG_PATH" "$KERNEL_2_ELF" > "$CONFIG_2"

"$HARDENING_CHECKER_PATH" -c "$CONFIG_1" > "$SEC_1"
"$HARDENING_CHECKER_PATH" -c "$CONFIG_2" > "$SEC_2"



python3 diff_kernel_hardening.py "$SEC_1" "$SEC_2" > "$KERNEL_DIGEST_FILE"



