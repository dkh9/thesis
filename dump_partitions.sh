#!/bin/bash

ANDSCANNER_PATH=/home/dasha/thesis/tools/AndScanner
USER_PARTITIONS="userspace_partitions"
SAM_PATTERN="AP_*.tar.md5.extracted*"
F2FS_POINT="/mnt/f2fs-point/"

if [ $# -eq 0 ]
  then
    echo "Usage: dump_partitions.sh <fw_archive> [output_dir]"
    exit 1
fi

source=$1

if [ $# -ne 1 ]
    then
        dest=$2
    else
        dest="${1%/*}/"
fi

extract_archive() {
    echo "Extracting archive $1 to $2"
    unpack_cmd="python scan.py $1 $2 --extract"
    pushd .
    cd $ANDSCANNER_PATH
    source venv/bin/activate
    eval $unpack_cmd
    deactivate
    popd
}

unpack_super() {

for img in super*.img 
    do
        if file $img | grep -q "Android sparse image"; then
            echo "Found sparse $img!"
            raw="${img%.img}.raw" 
            simg2img "$img" "$raw" 
        else
            echo "SKIPPING: $img not sparse!"
            exit 1 
        fi  
    done

for raw in super*.raw
    do 
    #folder="${raw%.raw}"; 
    lpunpack "$raw" .
    done
}

unpack_img() {
    img=$1
    userspace_collection=$2
    
    #no_ext="${img%.img}"
    no_ext="${img%.*}" #no_ext="${img%%.*}" may be useful for the future
    mount_point="${F2FS_POINT}${no_ext}"

    if file $img | grep -q "F2FS filesystem"; then 
        echo "Mount point: $mount_point"
        sudo mkdir -p $mount_point
        sudo mount -o loop -t f2fs $img $mount_point
        sudo rsync -ah $mount_point $userspace_collection
        sudo umount $mount_point
    
    elif file $img | grep -q "EROFS filesystem"; then 
        echo "Mount point: $mount_point"
        sudo mkdir -p $mount_point
        sudo mount -o loop -t erofs $img $mount_point
        sudo rsync -ah $mount_point $userspace_collection
        sudo umount $mount_point

    elif file $img | grep -q "ext2 filesystem"; then 
        echo "Mount point: $mount_point"
        sudo mkdir -p $mount_point
        sudo mount -o loop $img $mount_point
        sudo rsync -ah $mount_point $userspace_collection
        sudo umount $mount_point
    
    elif file $img | grep -q "ext4 filesystem"; then 
        echo "Mount point: $mount_point"
        sudo mkdir -p $mount_point
        sudo mount -o loop $img $mount_point
        sudo rsync -ah $mount_point $userspace_collection
        sudo umount $mount_point

    elif file $img | grep -q "Android sparse image"; then
        echo "Found sparse $img!"
        raw="${img%.img}.raw" 
        simg2img "$img" "$raw"
        unpack_img $raw $userspace_collection
    fi
}

unpack_user_partitions() {
    target_files=("vendor.img" "vendor_a.img" "vendor_b.img" 
                "system.img" "system_a.img" "system_b.img" "system_ext.img" "system_other.img"
                "product.img" "product_a.img" "product_b.img" 
                "odm.img" "userdata.img")
    search_dir=$1

    for file in "${target_files[@]}"; do
        if [[ -f "$search_dir/$file" ]]; then
            found_files+=("$file")
        fi
        done

    echo "Found files: ${found_files[@]}"

    for file in "${found_files[@]}"; do
        extracted_dir="${file}.extracted"
        
        if [ -d $extracted_dir ]; then
            echo "Already unpacked!"
            extless="${file%.img}"
            dest_folder="$USER_PARTITIONS/$extless"
            echo "Dest folder: $dest_folder"
            mv $extracted_dir $dest_folder

        else
            unpack_img $file $USER_PARTITIONS
        fi

        
        done
    

}

#-----------------------
extract_archive $source $dest

extracted_folder_name="${1##*/}.extracted"
full_extracted_path="${dest}${extracted_folder_name}"

echo "Full extracted path: "
echo "$full_extracted_path"

matching_folder=("$full_extracted_path"/$SAM_PATTERN/) 
if [[ -d "${matching_folder[0]}" ]]; then
    partitions_folder="${matching_folder[0]}"
else 
    search_res="$(find $full_extracted_path -name boot.img)"
    partitions_folder="${search_res%/*}/"
fi

echo "Partitions folder: $partitions_folder"

if [ -z "$partitions_folder" ]; then
    echo "ERROR: no partitions folder found!"
    exit 1
fi

pushd .

cd $partitions_folder
pwd
unpack_super

#4. after that unpacking, look for partitions of interest from the list: system.img, vendor.img, odm, product, userdata etc.
#4.5 check is parition.img.extracted exists, if so, move it $USER_PARTITIONS, otherwise, unpack myself
#5. unpack them into user_partitions

mkdir $USER_PARTITIONS
unpack_user_partitions .

popd
