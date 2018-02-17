OUT_DIR ?= build
KERNEL = $(OUT_DIR)/kernel
GRUB_CFG = grub_default.cfg
ISO = hyper.iso

INCLUDE_DIR = include/
OBJS = src/boot.o \
       src/main.o \
       src/write.o

LIBC_DIR=src/libc
LIBC_OBJS=$(LIBC_DIR)/printf.o \
	  $(LIBC_DIR)/strlen.o \
	  $(LIBC_DIR)/strnlen.o \
	  $(LIBC_DIR)/puts.o

CC=gcc
CPPFLAGS += -I$(INCLUDE_DIR) -I$(LIBC_DIR)/include
CFLAGS = -Wall -Wextra -Werror -std=gnu99 -g3 -fno-stack-protector \
	 -fno-builtin -ffreestanding

ASFLAGS += -g3
LDFLAGS = -n -T $(LDSCRIPT) -nostdlib
LDSCRIPT = src/hyper.lds

.PHONY: all clean run iso

all: $(ISO)
	
iso: $(ISO)

run: $(ISO)
	qemu-system-x86_64 -cdrom $(ISO) -enable-kvm -serial stdio

$(ISO): $(OUT_DIR) $(KERNEL) 
	mkdir -p $(OUT_DIR)/iso/boot/grub
	cp $(KERNEL) $(OUT_DIR)/iso/boot/kernel
	cp $(GRUB_CFG) $(OUT_DIR)/iso/boot/grub/grub.cfg
	grub-mkrescue -o $(ISO) $(OUT_DIR)/iso

$(KERNEL): $(OBJS) $(LIBC_OBJS)
	$(LD) $(LDFLAGS) -o $@ $?

$(OUT_DIR):
	mkdir -p $(OUT_DIR)
clean:
	$(RM) -r $(OUT_DIR)
	$(RM) $(OBJS)
	$(RM) $(LIBC_OBJS)
	$(RM) $(ISO)

