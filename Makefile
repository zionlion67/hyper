# TODO Recursive makefiles or equivalent, this is ...
OUT_DIR ?= build
KERNEL = $(OUT_DIR)/kernel
ISO = hyper.iso

QEMU=/usr/bin/qemu-system-x86_64
QEMU_OPTS= -drive id=disk,file=$(ISO),if=none \
	     -device ahci,id=ahci		\
	     -device ide-drive,drive=disk,bus=ahci.0 \
	     -serial stdio -m 4G
#QEMU_OPTS=-cdrom $(ISO) -serial stdio -m 4G

INCLUDE_DIR = include/
OBJS = src/boot.o 	\
       src/main.o	\
       src/write.o	\
       src/isr.o	\
       src/interrupts.o \
       src/page_alloc.o \
       src/kmalloc.o	\
       src/tss.o	\
       src/vmx.o	\
       src/vmx_guest_test.o \
       src/vm_exit.o	\
       src/vmx_debug.o	\
       src/pci.o	\
       src/pci_driver.o \
       src/vm_iodev.o	\
       src/uart_8250.o

LIBC_DIR=src/libc
LIBC_OBJS=$(LIBC_DIR)/printf.o \
	  $(LIBC_DIR)/strlen.o \
	  $(LIBC_DIR)/strnlen.o \
	  $(LIBC_DIR)/puts.o	\
	  $(LIBC_DIR)/memset.o  \
	  $(LIBC_DIR)/memcpy.o	\
	  $(LIBC_DIR)/strcmp.o	\
	  $(LIBC_DIR)/strncmp.o \
	  $(LIBC_DIR)/strstr.o

DRIVER_DIR=src/drivers
DRIVER_OBJS=$(DRIVER_DIR)/ahci.o

CC=gcc
CPPFLAGS += -I$(INCLUDE_DIR) -I$(LIBC_DIR)/include #-DDEBUG
CFLAGS += -Wall -Wextra -Werror -std=gnu99 -g3 -fno-stack-protector \
	 -fno-builtin -ffreestanding -Wno-int-conversion -fno-plt

ASFLAGS += -g3
LDFLAGS = -n -T $(LDSCRIPT) -nostdlib -static
LDSCRIPT = src/hyper.lds

.PHONY: all clean run debug debug_io

all: $(ISO)

run: $(ISO)
	$(QEMU) $(QEMU_OPTS) -cpu host -enable-kvm

debug: CFLAGS+= -DDEBUG
debug: $(ISO)
	$(QEMU) $(QEMU_OPTS) -s -S

debug_io: CFLAGS+=-DDEBUG_IO
debug_io: $(ISO)

$(ISO): $(OUT_DIR) $(KERNEL)
	./tools/create_iso.sh $(realpath $(OUT_DIR)) $(ISO)

$(KERNEL): $(OBJS) $(LIBC_OBJS) $(DRIVER_OBJS)
	$(LD) $(LDFLAGS) -o $@ $?

$(OUT_DIR):
	mkdir -p $(OUT_DIR)
clean:
	$(RM) -r $(OUT_DIR)
	$(RM) $(OBJS)
	$(RM) $(LIBC_OBJS)
	$(RM) $(DRIVER_OBJS)
	$(RM) $(ISO)

