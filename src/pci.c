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

#define PCI_NR_CLASS 0x12
static const char *__pci_dev_class_str[PCI_NR_CLASS] = {
	"Class not supported",
	"Mass storage controller",
	"Network controller",
	"Display controller",
	"Multimedia controller",
	"Memory controller",
	"Bridge device",
	"Simple communication controllers",
	"Base System Peripherals",
	"Input Devices",
	"Docking stations",
	"Processors",
	"Serial bus controller",
	"Wireless controller",
	"Intelligent I/O controller",
	"Satellite Communication controller",
	"Encryption/Decryption controller",
	"Data acquisition and signal processing controller",
};

static inline const char *pci_dev_class_str(const u8 class)
{
	if (class < PCI_NR_CLASS)
		return __pci_dev_class_str[class];
	else if (class != 0xff)
		return "Reserved";
	else
		return "Not defined";
}

static void pci_print_config_common(struct pci_config_common *config)
{
	printf("VendorID: 0x%x\tDeviceID: 0x%x\tClass: %s (0x%x)\n",
			config->vendor_id, config->device_id,
			pci_dev_class_str(config->class), config->class);
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
