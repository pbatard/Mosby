#!/bin/env bash
# !!!THIS SCRIPT IS FOR INTERNAL DEVELOPER USE ONLY!!!

export WORKSPACE=$PWD
export PACKAGES_PATH=$WORKSPACE:$WORKSPACE/edk2
source edk2/edksetup.sh
build -a X64 -b RELEASE -t GCC5 -p TurnKeyPkg.dsc
mkdir -p image/efi/boot
cp Build/RELEASE_GCC5/X64/TurnKey.efi image/efi/boot/bootx64.efi
export QEMU_CMD="qemu-system-x86_64 -M q35 -L . -drive if=pflash,format=raw,unit=0,file=OVMF.fd,readonly=on -drive format=raw,file=fat:rw:image -nodefaults -nographic -serial stdio -net none"

