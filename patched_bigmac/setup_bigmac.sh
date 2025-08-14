#!/bin/bash

cd BigMAC/
virtualenv -p python3 venv
source venv/bin/activate

git clone https://github.com/jakev/sefcontext-parser
cd sefcontext-parser
python3 setup.py install

apt-add-repository ppa:swi-prolog/stable
apt-get update
apt-get install swi-prolog
cd ..

git clone --branch libsepol-2.7 https://github.com/SELinuxProject/selinux.git
cd selinux
patch -p1 < ../selinux.patch
export CFLAGS="$CFLAGS -I/opt/BigMAC/BigMAC/selinux/libsepol/include/"
export LDFLAGS="$LDFLAGS -L/opt/BigMAC/BigMAC/selinux/libsepol/src/"
export CFLAGS="$CFLAGS -I/opt/BigMAC/BigMAC/selinux/libselinux/include/"
make -j
make install
cd ..

git clone https://github.com/TresysTechnology/setools.git
cd setools
git checkout 856b56accba14 # required to match with libsepol version
patch -p1 < ../setools.patch
SEPOL_SRC=$(pwd)/../selinux/libsepol/ python3 setup.py build_ext build_py install
cd ..

pip install -r requirements.txt

#BigMAC setup done, now unpacking tools

tar -xzf ../android-extract.tar.gz -C tools/
cp ../patched_tool_setup.sh tools/atsh_setup/
cp -r ../java_patches tools/atsh_setup/
cd tools/atsh_setup/
./patched_tool_setup.sh
