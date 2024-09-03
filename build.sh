#!/bin/env bash

if [ $(hostname) != "nas" ]; then
  echo THIS SCRIPT IS FOR INTERNAL DEVELOPER USE ONLY\!
  return 1
fi

export WORKSPACE=$PWD
export PACKAGES_PATH=$WORKSPACE:$WORKSPACE/edk2
source edk2/edksetup.sh
build -a X64 -b RELEASE -t GCC5 -p MosbyPkg.dsc
cp Build/RELEASE_GCC5/X64/Mosby.efi image
# QEMU execution is much faster when '-enable-kvm -cpu host' can be used. However this requires root 
if [ "$EUID" -eq 0 ]; then
  CPU_OPT="-enable-kvm -cpu host"
else
  # EDK2's OpenSSL implementation requires IvyBridge or later to function for RDRAND
  CPU_OPT="-cpu IvyBridge"
fi
# DISABLED = SecureBoot=0, SetupMode=0
# SETUP = SecureBoot=0, SetupMode=1
SB_MODE=SETUP
cp OVMF_VARS_4M.secboot.$SB_MODE.fd OVMF_VARS_4M.secboot.fd
export QEMU_CMD="qemu-system-x86_64 $CPU_OPT -m 1024 -M q35 -L . \
  -drive if=pflash,format=raw,unit=0,file=OVMF_CODE_4M.secboot.fd,readonly=on \
  -drive if=pflash,format=raw,unit=1,file=OVMF_VARS_4M.secboot.fd \
  -drive format=raw,file=fat:rw:image -nodefaults -nographic -serial stdio -net none"
