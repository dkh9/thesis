# Installation prerequisites
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
Set the HARDENING_CHECKER_PATH accordingly
Make sure to copy over https://github.com/torvalds/linux/blob/master/scripts/extract-ikconfig, set it to executable and set EXTRACT_IKCONFIG_PATH accordingly

Make sure to install vmlinux-to-elf as well, set VMLINUX_TO_ELF variable accordingly
```
git clone https://github.com/marin-m/vmlinux-to-elf
```

Then, provide 2 folders with boot.img for comparison. The expected structure is boot_img_folder_1/boot.img, boot_img_folder_2/boot.img

```
./check_kernel_config.sh boot_img_folder_1 boot_img_folder_2
```

## 2. Bins/libs


```
pacman -S radare2 zip unzip 
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
## 5. BigMAC

Please make sure you have docker up and running on your system.