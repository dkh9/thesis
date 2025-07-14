#!/bin/bash

set -euo pipefail

# Check argument
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <firmware_path>"
    exit 1
fi

fw_path="$1"
mnt_point="/mnt/apex_point"

# Ensure mount point exists
sudo mkdir -p "$mnt_point"

# Find all .apex files
mapfile -t apex_files < <(find "$fw_path" -iname "*.apex")

for apex_file in "${apex_files[@]}"; do
    echo "Processing: $apex_file"

    # Create output directory
    unzip_dir="${apex_file}.unzipped"
    mkdir -p "$unzip_dir"

    # Unzip the .apex file
    unzip -q "$apex_file" -d "$unzip_dir"

    # Check for apex_payload.img
    payload_img="$unzip_dir/apex_payload.img"
    if [[ ! -f "$payload_img" ]]; then
        echo "  No apex_payload.img found in $unzip_dir. Skipping."


        if rm "$apex_file"; then
            echo "  Deleted $apex_file"
        else
            echo "  Failed to delete $apex_file"
        fi
        continue
    fi

    # Mount the image
    echo "  Mounting $payload_img to $mnt_point"
    sudo mount -o ro -t ext4 "$payload_img" "$mnt_point"

    # Copy contents
    contents_dir="$unzip_dir/apex_payload_contents"
    mkdir -p "$contents_dir"
    sudo cp -a "$mnt_point/." "$contents_dir/"

    # Unmount
    echo "  Unmounting $mnt_point"
    sudo umount "$mnt_point"

    echo "  Done processing $apex_file"
    if rm "$apex_file"; then
        echo "  Deleted $apex_file"
    else
        echo "  Failed to delete $apex_file"
    fi
done

echo "All APEX files processed."
