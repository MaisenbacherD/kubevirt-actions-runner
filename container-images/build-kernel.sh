#!/bin/bash
set -e
set -x

git config --global --add safe.directory '*'
mkdir -p linux
cd linux
git init
git remote add origin https://github.com/kawasaki/linux-block.git
#TODO: make this variable
git fetch origin --depth=5 baf2b35293fde7a755e49935f331d1e914d7b4bb
git reset --hard baf2b35293fde7a755e49935f331d1e914d7b4bb
git log -1
cp /config-6.13.5-200.fc41.x86_64 /linux/.config
make defconfig
make -j$(nproc)
#make modules_install
#make install
#dracut --kver ${KERNEL_VERSION} --force

mv /linux/arch/x86_64/boot/bzImage /output
