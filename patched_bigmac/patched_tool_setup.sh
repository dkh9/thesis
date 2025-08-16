#!/bin/bash
sudo git clone https://android.googlesource.com/platform/system/tools/mkbootimg/
PATH_RECORD=path_record.txt
#rm -rf android-simg2img/
#git clone https://github.com/anestisb/android-simg2img.git
#cd android-simg2img && make  && cp simg2img /bin
#which simg2img

mkdir dex2jar/dex-tools/lib
cp java_patches/dx-23.0.0.jar dex2jar/dex-tools/lib/
cd dex2jar
mvn install:install-file \
  -Dfile=./dex-tools/lib/dx-23.0.0.jar \
  -DgroupId=com.google.android.tools \
  -DartifactId=dx \
  -Dversion=23.0.0 \
  -Dpackaging=jar
mvn clean package 
cd dex-tools/target
unzip dex2jar-2.1-SNAPSHOT.zip
cd dex2jar-2.1-SNAPSHOT
echo "DEX2JAR=`pwd`/d2j-dex2jar.sh" > $PATH_RECORD
cd ../../../../
pwd

rm -rf jd-cmd
git clone https://github.com/intoolswetrust/jd-cli.git
mkdir jd-cli/jd-lib/lib
cp java_patches/jd-core-1.1.3.jar jd-cli/jd-lib/lib
cd jd-cli
mvn install:install-file \
  -Dfile=./jd-lib/lib/jd-core-1.1.3.jar \
  -DgroupId=org.jd \
  -DartifactId=jd-core \
  -Dversion=1.1.3 \
  -Dpackaging=jar
mvn clean package
cd jd-cli/target
echo "JDCLI=`pwd`/jd-cli.jar" >> $PATH_RECORD
cd ../../../

wget https://bitbucket.org/JesusFreke/smali/downloads/smali-2.5.2.jar
wget https://bitbucket.org/JesusFreke/smali/downloads/baksmali-2.5.2.jar
echo "BAKSMALI=`pwd`/baksmali-2.5.2.jar" >> $PATH_RECORD
echo "SMALI=`pwd`/smali-2.5.2.jar" >> $PATH_RECORD

rm -rf jadx
git clone https://github.com/skylot/jadx.git
cd jadx
./gradlew dist
cd build/jadx/bin
echo "JADX=`pwd`/jadx" >> $PATH_RECORD
cd ../../../../

https://android.googlesource.com/platform/system/tools/mkbootimg

git clone https://github.com/erofs/erofs-utils.git
cd erofs-utils
./autogen.sh
./configure
make
make install
cd ..

git clone https://github.com/Exynos-nibba/lpunpack-lpmake-mirror
cd lpunpack-lpmake-mirror/
chmod +x install.sh
./install.sh
cd ..
