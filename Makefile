OUT_DIR ?= build
KERNEL = $(OUT_DIR)/kernel
GRUB_CFG = grub_default.cfg
ISO = hyper.iso

INCLUDE_DIR = include/
OBJS = src/boot.o \
       src/main.o

CC=gcc
CPPFLAGS += -I$(INCLUDE_DIR)
CFLAGS = -Wall -Wextra -Werror -std=gnu99 -nostdinc -g3

ASFLAGS += -g3
LDFLAGS = -n -T $(LDSCRIPT) -nostdlib
LDSCRIPT = src/hyper.lds

.PHONY: all clean run iso

all: $(ISO)
	
iso: $(ISO)

run: $(ISO)
	qemu-system-x86_64 -cdrom $(ISO) -enable-kvm

$(ISO): $(OUT_DIR) $(KERNEL) 
	mkdir -p $(OUT_DIR)/iso/boot/grub
	cp $(KERNEL) $(OUT_DIR)/iso/boot/kernel
	cp $(GRUB_CFG) $(OUT_DIR)/iso/boot/grub/grub.cfg
	grub-mkrescue -o $(ISO) $(OUT_DIR)/iso

$(KERNEL): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $?

$(OUT_DIR):
	mkdir -p $(OUT_DIR)
clean:
	$(RM) -r $(OUT_DIR)
	$(RM) $(OBJS)
	$(RM) $(ISO)

