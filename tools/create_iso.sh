#!/bin/sh

# $1 is the build directory realpath
# $2 is the iso name

[ "$#" -ne 2 ] && echo "usage: $0 <build_dir> <iso_name>" >&2 && exit 1

OUT_DIR="$1"
ISO="$2"
ISO_PATH="$OUT_DIR/iso"
GRUB_CFG="grub_default.cfg"

LINUX_PATH=~/linux_mykvm/obj/linux-defconfig/arch/x86/boot/bzImage
INITRAMFS_PATH=~/linux_mykvm/obj/initramfs_test.img

mkdir -p "$ISO_PATH/boot/grub"
cp "$OUT_DIR/kernel" "$ISO_PATH/boot/kernel"
cp "$GRUB_CFG" "$ISO_PATH/boot/grub/grub.cfg"

ISO_LINUX_DIR="$ISO_PATH/linux"

mkdir -p "$ISO_LINUX_DIR"
cp "$LINUX_PATH" "$ISO_LINUX_DIR"
cp "$INITRAMFS_PATH" "$ISO_LINUX_DIR"

grub-mkrescue -o "$ISO" "$ISO_PATH"
