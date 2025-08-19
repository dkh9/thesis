# Installation prerequisites
This installation guide is applicable to Arch-based systems btw
## 0. Unpacking

```
git clone https://github.com/ernstleierzopf/AndScanner
pacman -S android-tools 7zip
```


Adjust ANDSCANNER_PATH in dump_partitions.sh accordingly with your local path to the AndScanner. In the corresponding folder, 
satisfy the setup reqiuements for the AndScanner

```
python -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

Then, call the ./dump_partitions.sh

```
./dump_partitions.sh <fw_archive> [output_dir]
```

After unpacking, the userspace_partitions/ and boot_partition/ will be in the extracted folder

## 1. Kernel
```
git clone https://github.com/a13xp0p0v/kernel-hardening-checker
```
Set the HARDENING_CHECKER_PATH accordingly (path to the binary of the checker)
Make sure to copy over https://github.com/torvalds/linux/blob/master/scripts/extract-ikconfig, set it to executable and set EXTRACT_IKCONFIG_PATH accordingly

Make sure to install vmlinux-to-elf as well, set VMLINUX_TO_ELF variable accordingly (symlink to vmlinux_to_elf/main.py)
```
git clone https://github.com/marin-m/vmlinux-to-elf
```

Then, provide 2 paths to boot.img for comparison

```
./check_kernel_config.sh path/to/boot_1.img path/to/boot_2.img
```

The output will be provided as kernel_diget.json in the check_1_kernel/ folder.

## 2. Bins/libs


```
pacman -S radare2 zip unzip checksec
```
We also need sediff to check whether the precompiled SELinux policy has changed
```
yay -S setools
```

## 3. Permissions checks

```
pacman -S jadx
```

Unfortunately, the apktool was only available through AUR, as well as android-sdk-build-tools (for aapt2) and android-sdk-cmdline-tools (for apkanalyzer).

```
yay -S android-apktool-bin android-sdk-build-tools android-sdk-cmdline-tools
```

In order to run the analysis, do:

```
./run_all_checks.sh userspace_partitions_1/ userspace_partitions_2/
```
result_digests/ and intermediate_files/ will have the corresponding contents with the final results and additional info respectively.


Great page in general btw: https://wiki.archlinux.org/title/Android

## 4. CA cert
Does not require extra setup, run:
```
```

## 5. BigMAC
Prerequisites: install the filesystem support tools
```
pacman -S erofs-utils f2fs-tools
```
Also, make sure you have git-lfs
```
pacman -S git-lfs
git lfs-pull
```


Please make sure you have docker up and running on your system.
Then, change to the docker-build/ folder and run 
```
docker build -t bigmac-container .
```
Before starting the container, make sure to have all the loop devices ready:
```
mknod /dev/loop0 b 7 0
mknod /dev/loop1 b 7 1
...
sudo usermod -aG disk $USER
```
Make sure to have around 10 loop interfaces created
Now, start the cointainer, mounting it to the patched_bigmac folder here
```
docker run -it \
  --cap-add SYS_ADMIN \
  $(for i in {0..9}; do echo --device=/dev/loop$i:/dev/loop$i; done) \
  --mount type=bind,source=/home/cembelentepe/repos/thesis/patched_bigmac,target=/opt/BigMAC \
  --name bigmac-container \
  bigmac-container bash
```
You should be dropped to a shell. Now, call exit. Afterwards, you can start and stop the container in the following way:
```
docker start bigmac-container
docker stop bigmac-container
```
Enter into the running container:
```
docker exec -it bigmac-container bash
cd /opt/BigMAC
sudo ./setup_bigmac.sh
```
Make sure that on your host you have a pexpect package for python, feel free to have it either system-wide through AUR or in venv

