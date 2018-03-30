#include <io.h>
#include <stdio.h>
#include <compiler.h>

#define PCI_CONFIG_ADDRESS	0xCF8
#define PCI_CONFIG_DATA 	0xCFC

struct pci_addr {
	union {
		struct {
			u32	zero : 2;
			u32	reg : 6;
			u32	func : 3;
			u32	dev : 5;
			u32	bus : 8;
			u32	reserved : 7;
			u32	enable : 1;
		};
		u32 	dword;
	};
} __packed;

struct pci_command_reg {
	union {
		struct {
			u16	io_space : 1;
			u16	mem_space : 1;
			u16	bus_master : 1;
			u16	special_cycles : 1;
			u16	write_inv_enable : 1;
			u16	vga_snoop : 1;
			u16	parity_err : 1;
			u16	reserved1 : 1;
			u16	serr_enable : 1;
			u16	fbtb_enable : 1;
			u16	disable_irq : 1;
			u16	reserved2 : 5;
		};
		u16	word;
	};
} __packed;

struct pci_status_reg {
	union {
		struct {
			u16	reserved1 : 3;
			u16	irq_status : 1;
			u16	cap_list : 1;
			u16	_66_mhz_cap : 1;
			u16	reserved2 : 1;
			u16	fbtb_cap : 1;
			u16	master_data_parity_err : 1;
			u16	devsel_timing : 2;
			u16	sig_target_abort : 1;
			u16	rx_target_abort : 1;
			u16	rx_master_abort : 1;
			u16	sig_sys_err : 1;
			u16	parity_err : 1;
		};
		u16	word;
	};
} __packed;

struct pci_header_type {
	union {
		struct {
			u8	type : 7;
			u8	multiple_func : 1;
		};
		u8	byte;
	};
} __packed;

/* bist = Built-in Self Reset */
struct pci_bist_reg {
	union {
		struct {
			u8	comp_code : 4;
			u8	reserved : 2;
			u8	start_bist : 1;
			u8	bist_cap : 1;
		};
		u8	byte;
	};
} __packed;

struct pci_config_common {
	u16			vendor_id;
	u16			device_id;
	struct pci_command_reg 	command;
	struct pci_status_reg	status;
	u8			rev_id;
	u8			prog_if;
	u8			sub_class;
	u8			class;
	u8			cacheline_sz;
	u8			latency_timer;
	struct pci_header_type	header_type;
	struct pci_bist_reg	bist;
} __packed;

struct pci_dev_descr {
	u8		class;
	u8		sub_class;
	u8		prog_if;
	const char 	*descr;
};

static inline u32 pci_read_config_dword(const struct pci_addr addr)
{
	outl(PCI_CONFIG_ADDRESS, addr.dword);
	return inl(PCI_CONFIG_DATA);
}

static void pci_read_config_common(struct pci_addr addr,
				   struct pci_config_common *config)
{
	for (u16 i = 0; i < sizeof(struct pci_config_common) / sizeof(u32); i++) {
		addr.reg = i;
		u32 *tmp = (u8 *)config + i * sizeof(u32);
		*tmp = pci_read_config_dword(addr);
	}
}

#define ANY_IF 0xff
static struct pci_dev_descr __pci_dev_descrs[] = {
#define PCI_DESCR(Class, Sub, IF, Descr) { Class, Sub, IF, Descr }
	PCI_DESCR(0x00, 0x00, 0x00, 	"Any device except VGA-compatibles"),
	PCI_DESCR(0x00, 0x01, 0x00, 	"VGA-Compatible Device"),

	/* Mass Storage Controllers */
	PCI_DESCR(0x01, 0x00, 0x00, 	"SCSI Bus Controller"),
	PCI_DESCR(0x01, 0x01, ANY_IF,	"IDE Controller"),
	PCI_DESCR(0x01, 0x02, 0x00,	"Floppy Disk Controller"),
	PCI_DESCR(0x01, 0x03, 0x00,	"IPI Bus controller"),
	PCI_DESCR(0x01, 0x04, 0x00,	"RAID Controller"),
	PCI_DESCR(0x01, 0x05, 0x20,	"ATA Controller (Single DMA)"),
	PCI_DESCR(0x01, 0x05, 0x30,	"ATA Controller (Chained DMA)"),
	PCI_DESCR(0x01, 0x06, 0x00,	"SATA Controller"),
	PCI_DESCR(0x01, 0x06, 0x01,	"SATA Controller (AHCI 1.0 Mode)"),
	PCI_DESCR(0x01, 0x07, 0x00,	"Serial Attached SCSI"),
	PCI_DESCR(0x01, 0x80, ANY_IF,	"Other Mass Storage Controller"),

	/* Network controllers */
	PCI_DESCR(0x02, 0x00, 0x00,	"Ethernet Controller"),
	PCI_DESCR(0x02, 0x01, 0x00,	"Token Ring Controller"),
	PCI_DESCR(0x02, 0x02, 0x00,	"FDDI Controller"),
	PCI_DESCR(0x02, 0x03, 0x00,	"ATM Controller"),
	PCI_DESCR(0x02, 0x04, 0x00,	"ISDN Controller"),
	PCI_DESCR(0x02, 0x05, 0x00,	"WorldFip Controller"),
	PCI_DESCR(0x02, 0x06, ANY_IF,	"PICMG 2.14 Multi Computing"),
	PCI_DESCR(0x02, 0x80, ANY_IF,	"Other Network Controller"),

	/* Display Controllers */
	PCI_DESCR(0x03, 0x00, 0x00,	"VGA-Compatible Controller"),
	PCI_DESCR(0x03, 0x00, 0x01,	"8512-Compatible Controller"),
	PCI_DESCR(0x03, 0x01, 0x00,	"XGA Controller"),
	PCI_DESCR(0x03, 0x02, 0x00,	"3D Controller (Not VGA-Compatible"),
	PCI_DESCR(0x03, 0x80, ANY_IF,	"Other Display Controller"),

	/* Multimedia Controller */
	PCI_DESCR(0x04, 0x00, 0x00,	"Video Device"),
	PCI_DESCR(0x04, 0x01, 0x00,	"Audio Device"),
	PCI_DESCR(0x04, 0x02, 0x00,	"Computer Telephony Device"),
	PCI_DESCR(0x04, 0x80, ANY_IF,	"Other Multimedia Device"),

	/* Memory Controllers */
	PCI_DESCR(0x05, 0x00, 0x00,	"RAM Controller"),
	PCI_DESCR(0x05, 0x01, 0x00,	"Flash Controller"),
	PCI_DESCR(0x05, 0x80, 0x00,	"Other Memory Controller"),

	/* Bridge Devices */
	PCI_DESCR(0x06, 0x00, 0x00,	"Host Bridge"),
	PCI_DESCR(0x06, 0x01, 0x00,	"ISA Bridge"),
	PCI_DESCR(0x06, 0x02, 0x00,	"EISA Bridge"),
	PCI_DESCR(0x06, 0x03, 0x00,	"MCA Bridge"),
	PCI_DESCR(0x06, 0x04, 0x00,	"PCI-to-PCI Bridge"),
	PCI_DESCR(0x06, 0x04, 0x01,	"PCI-to-PCI Bridge (Substractive Decode)"),
	PCI_DESCR(0x06, 0x05, 0x00,	"PCMCIA Bridge"),
	PCI_DESCR(0x06, 0x06, 0x00,	"NuBus Bridge"),
	PCI_DESCR(0x06, 0x07, 0x00,	"CardBus Bridge"),
	PCI_DESCR(0x06, 0x08, ANY_IF,	"RACEway Bridge"),
	PCI_DESCR(0x06, 0x09, 0x40,	"PCI-to-PCI Bridge (Semi-Transparent, Primary"),
	PCI_DESCR(0x06, 0x09, 0x41,	"PCI-to-PCI Bridge (Semi-Transparent, Secondary"),
	PCI_DESCR(0x06, 0x0a, 0x00,	"InfiniBrand-to-PCI Host Bridge"),
	PCI_DESCR(0x06, 0x80, ANY_IF,	"Other Bridge Device"),

	/* Communication Device */
	PCI_DESCR(0x07, 0x00, 0x00,	"Generic XT-Compatible Serial Controller"),
	PCI_DESCR(0x07, 0x00, 0x01,	"16450-Compatible Serial Controller"),
	PCI_DESCR(0x07, 0x00, 0x02,	"16550-Compatible Serial Controller"),
	PCI_DESCR(0x07, 0x00, 0x03,	"16650-Compatible Serial Controller"),
	PCI_DESCR(0x07, 0x00, 0x04,	"16750-Compatible Serial Controller"),
	PCI_DESCR(0x07, 0x00, 0x05,	"16850-Compatible Serial Controller"),
	PCI_DESCR(0x07, 0x00, 0x06,	"16950-Compatible Serial Controller"),
	PCI_DESCR(0x07, 0x01, 0x00,	"Parallel Port"),
	PCI_DESCR(0x07, 0x01, 0x01,	"Bi-Directional Parallel Port"),
	PCI_DESCR(0x07, 0x01, 0x02,	"ECP 1.X Compliant Parallel Port"),
	PCI_DESCR(0x07, 0x01, 0x03,	"IEEE 1284 Controller"),
	PCI_DESCR(0x07, 0x01, 0xfe,	"IEEE 1284 Target Device"),
	PCI_DESCR(0x07,	0x02, 0x00,	"Multiport Serial Controller"),
	PCI_DESCR(0x07, 0x03, 0x00,	"Generic Modem"),
	PCI_DESCR(0x07, 0x03, 0x00,	"Hayes Compatible Modem (16450 compat)"),
	PCI_DESCR(0x07, 0x03, 0x01,	"Hayes Compatible Modem (16550 compat)"),
	PCI_DESCR(0x07, 0x03, 0x02,	"Hayes Compatible Modem (16650 compat)"),
	PCI_DESCR(0x07, 0x03, 0x03,	"Hayes Compatible Modem (16750 compat)"),
	PCI_DESCR(0x07, 0x04, 0x00,	"IEEE 488.1/2 (GPIB) Controller"),
	PCI_DESCR(0x07, 0x05, 0x00,	"Smart Card"),
	PCI_DESCR(0x07, 0x80, 0x00,	"Other Communication Device"),

	/* Base System Peripherals */
	PCI_DESCR(0x08, 0x00, 0x00,	"Generic 8259 PIC"),
	PCI_DESCR(0x08, 0x00, 0x01,	"ISA PIC"),
	PCI_DESCR(0x08, 0x00, 0x02,	"EISA PIC"),
	PCI_DESCR(0x08, 0x00, 0x10,	"I/O APIC"),
	PCI_DESCR(0x08, 0x00, 0x20,	"I/O(x) APIC"),
	PCI_DESCR(0x08, 0x01, 0x00,	"Generic 8237 DMA Controller"),
	PCI_DESCR(0x08, 0x01, 0x01,	"ISA DMA Controller"),
	PCI_DESCR(0x08, 0x01, 0x02,	"EISA DMA Controller"),
	PCI_DESCR(0x08, 0x02, 0x00,	"Generic 8254 System Timer"),
	PCI_DESCR(0x08, 0x02, 0x01,	"ISA System Timer"),
	PCI_DESCR(0x08, 0x02, 0x02,	"EISA System Timer"),
	PCI_DESCR(0x08, 0x03, 0x00,	"Generic RTC Controller"),
	PCI_DESCR(0x08, 0x03, 0x01,	"ISA RTC Controller"),
	PCI_DESCR(0x08, 0x04, 0x00,	"Generic PCI Hot-Plug Controller"),
	PCI_DESCR(0x08, 0x80, ANY_IF,	"Other System Peripheral"),

	/* Input Controllers */
	/* TODO missing descriptions */

#undef PCI_DESCR
};

static inline int pci_descr_match(struct pci_config_common *c,
				  struct pci_dev_descr *d)
{
	return c->class == d->class && c->sub_class == d->sub_class
		&& (c->prog_if == d->prog_if || d->prog_if == ANY_IF);
}

static inline const char *pci_dev_descr(struct pci_config_common *c)
{
	for (u16 i = 0; i < array_size(__pci_dev_descrs); ++i) {
		struct pci_dev_descr *d = &__pci_dev_descrs[i];
		if (pci_descr_match(c, d))
			return d->descr;
	}
	return NULL;
}

static void pci_print_config_common(struct pci_config_common *config)
{
	const char *desc = pci_dev_descr(config);
	printf("VendorID: 0x%x\tDeviceID: 0x%x\tDevice: %s\n",
			config->vendor_id, config->device_id,
			desc == NULL ? "Unknown" : desc);
}

static void pci_print_config_addr(struct pci_addr addr,
				  struct pci_config_common *config)
{
	printf("%02x:%02x.%x\t", addr.bus, addr.dev, addr.func);
	pci_print_config_common(config);
}


#define PCI_INVALID_VENDOR_ID 0xffff
static void pci_bus_enum_dev_func(struct pci_addr addr,
				  struct pci_config_common *config)
{
	for (u8 f = 1; f < 8; ++f) {
		addr.func = f;
		pci_read_config_common(addr, config);
		if (config->vendor_id != PCI_INVALID_VENDOR_ID)
			pci_print_config_addr(addr, config);
	}
}


/* TODO add multiple functions support + real actions */
static void pci_bus_enum_devices(u8 bus) {

	struct pci_addr addr = {
		.bus = bus,
		.enable = 1,
	};

	for (u16 i = 0; i < 32; ++i) {
		addr.dev = i;
		struct pci_config_common config;
		pci_read_config_common(addr, &config);

		if (config.vendor_id == PCI_INVALID_VENDOR_ID)
			continue;

		pci_print_config_addr(addr, &config);

		if (config.header_type.multiple_func)
			pci_bus_enum_dev_func(addr, &config);
	}
	printf("\n");
}

int init_pci(void)
{
	printf("PCI devices:\n");
	pci_bus_enum_devices(0);
	return 0;
}
