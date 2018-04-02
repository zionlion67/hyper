#include <io.h>
#include <stdio.h>
#include <string.h>
#include <compiler.h>
#include <kmalloc.h>
#include <pci.h>

#define PCI_CONFIG_ADDRESS	0xCF8
#define PCI_CONFIG_DATA 	0xCFC

struct pci_addr {
	union {
		struct {
			u8	reg; /* MUST BE ALIGNED ON 4 !!! */
			u32	func : 3;
			u32	dev : 5;
			u32	bus : 8;
			u32	reserved : 7;
			u32	enable : 1;
		};
		u32 	dword;
	};
} __packed;


struct pci_dev_descr {
	u8		class;
	u8		sub_class;
	u8		prog_if;
	const char 	*descr;
};

static DECLARE_LIST(pci_drivers);

static inline u32 pci_inl(const struct pci_addr addr)
{
	outl(PCI_CONFIG_ADDRESS, addr.dword);
	return inl(PCI_CONFIG_DATA);
}

static void pci_read_config_common(struct pci_addr addr,
				   struct pci_config_common *config)
{
	for (u16 i = 0; i < sizeof(struct pci_config_common); i += sizeof(u32)) {
		addr.reg = i;
		u32 *tmp = (u8 *)config + i;
		*tmp = pci_inl(addr);
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

static const char *pci_dev_descr(struct pci_config_common *config)
{
	for (u16 i = 0; i < array_size(__pci_dev_descrs); ++i) {
		struct pci_dev_descr *descr = &__pci_dev_descrs[i];
		if (pci_descr_match(config, descr))
			return descr->descr;
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

static inline u32 pci_read_reg(struct pci_addr addr, u8 reg)
{
	addr.reg = reg;
	return pci_inl(addr);
}

#define PCI_CIS_PTR_REG 	0x28
#define PCI_SUBSYSTEM_REG	0x2c
#define PCI_EROM_REG		0x30
#define PCI_CAP_PTR_REG		0x34
#define PCI_INTR_REG		0x3c
static void pci_read_dev_config(struct pci_dev *pci_dev, struct pci_addr addr)
{
	/* Already read */
	u16 off = sizeof(struct pci_config_common);
	for (u16 i = 0; i < PCI_NR_BARS; ++i) {
		addr.reg = off + i;
		pci_dev->bars[i] = pci_inl(addr);
	}

	pci_dev->cis_ptr = pci_read_reg(addr, PCI_CIS_PTR_REG);

	u32 tmp = pci_read_reg(addr, PCI_SUBSYSTEM_REG);
	pci_dev->subvendor_id = tmp & 0xffff;
	pci_dev->subsystem_id = tmp >> 16;

	pci_dev->rom_addr = pci_read_reg(addr, PCI_EROM_REG);
	pci_dev->cap_ptr = pci_read_reg(addr, PCI_CAP_PTR_REG) & 0xff;

	tmp = pci_read_reg(addr, PCI_INTR_REG);
	*(u32 *)&pci_dev->intr_line = tmp;
}

#define PCI_INVALID_VENDOR_ID 0xffff
static int pci_bus_enum_dev_func(struct pci_bus *pci_bus, struct pci_addr addr,
				 struct pci_config_common *config)
{
	pci_read_config_common(addr, config);
	if (config->vendor_id == PCI_INVALID_VENDOR_ID)
		return 0;

	pci_print_config_addr(addr, config);

	struct pci_dev *pci_dev = kmalloc(sizeof(struct pci_dev));
	if (pci_dev == NULL)
		return 1;

	pci_dev->dev.desc = pci_dev_descr(config);
	pci_dev->dev.bus = &pci_bus->bus;

	memcpy(&pci_dev->common, config, sizeof(struct pci_config_common));
	pci_read_dev_config(pci_dev, addr);

	list_add(&pci_bus->bus.devices, &pci_dev->next);

	struct pci_device_id id = {
		PCI_DEVICE(config->vendor_id, config->device_id),
	};

	struct pci_driver *pci_drv = pci_find_driver(&id);
	if (pci_drv == NULL) {
		pci_dev->dev.drv = NULL;
	} else {
		if (pci_driver_probe(pci_drv, pci_dev))
			pci_dev->dev.drv = &pci_drv->drv;
	}

	return 0;
}

#define PCI_NR_FUNC 8
static int pci_bus_enum_device(struct pci_bus *bus, struct pci_addr addr)
{
	for (u8 func = 0; func < PCI_NR_FUNC; ++func) {
		addr.func = func;
		struct pci_config_common config;
		if (pci_bus_enum_dev_func(bus, addr, &config))
			return 1;
		if (!config.header_type.multiple_func)
			break;
	}

	return 0;
}

#define PCI_NR_DEVICE 32
static int pci_bus_enum_devices(struct bus *bus)
{
	struct pci_bus *pci_bus = to_pci_bus(bus);

	struct pci_addr addr = {
		.bus = pci_bus->num,
		.enable = 1,
	};

	for (u16 i = 0; i < PCI_NR_DEVICE; ++i) {
		addr.dev = i;
		if (pci_bus_enum_device(pci_bus, addr))
			return 1;
	}

	printf("\n");
	return 0;
}

static const struct bus_ops pci_bus_ops = {
	.discover = pci_bus_enum_devices,
};

int init_pci_bus(struct pci_bus *pci_bus)
{
	return bus_init(&pci_bus->bus, "PCI Bus", &pci_bus_ops);
}
