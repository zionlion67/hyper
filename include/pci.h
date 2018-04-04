#ifndef _PCI_H_
#define _PCI_H_

#include "types.h"
#include "device.h"

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

struct pci_bus {
	struct bus bus;
	u8 num;
};

#define to_pci_bus(n) container_of((n), struct pci_bus, bus)

#define PCI_NR_BARS 6
struct pci_driver;
struct pci_dev {
	struct device 		 dev;
	struct pci_config_common common;
	u32 			 bars[PCI_NR_BARS];
	u32			 cis_ptr;
	u16			 subvendor_id;
	u16			 subsystem_id;
	u32			 rom_addr;
	u8			 cap_ptr;
	u8			 intr_line;
	u8			 intr_pin;
	u8			 min_grant;
	u8			 max_latency;

	struct list next;
};

#define to_pci_dev(n) container_of((n), struct pci_dev, dev)

struct pci_device_id {
	u16	vendor_id;
	u16	device_id;
	u16	subvendor_id;
	u16	subsystem_id;
};

#define PCI_ANY_ID 0xff
#define PCI_DEVICE(vend, dev) 			\
  .vendor_id = (vend),				\
  .device_id = (dev),				\
  .subvendor_id = PCI_ANY_ID,			\
  .subsystem_id = PCI_ANY_ID			\


/* Could be one line but i found it clearer with ifs */
static inline int pci_id_match(struct pci_device_id*id1,
			       struct pci_device_id *id2)
{
	if (id1->vendor_id != id2->vendor_id || id1->device_id != id2->device_id)
		return 0;

	if (id1->subvendor_id != id2->subvendor_id)
		if (id1->subvendor_id != PCI_ANY_ID
		    && id2->subvendor_id != PCI_ANY_ID)
			return 0;

	if (id1->subsystem_id != id2->subsystem_id)
		if (id1->subsystem_id != PCI_ANY_ID
		    && id2->subsystem_id != PCI_ANY_ID)
			return 0;
	return 1;
}

struct pci_driver {
	struct device_driver 	drv;
	struct pci_device_id 	*id;
	struct list 		next; /* list of all pci drivers */
};

static inline int pci_driver_probe(struct pci_driver *pci_drv,
				   struct pci_dev *pci_dev)
{
	return pci_drv->drv.ops->probe(&pci_dev->dev);
}

int init_pci_bus(struct pci_bus *);
int pci_register_driver(struct pci_driver *driver);
int pci_register_drivers(void);
struct pci_driver *pci_find_driver(struct pci_device_id *id);

static inline void pci_bus_discover(struct pci_bus *pci_bus)
{
	pci_bus->bus.bus_ops->discover(&pci_bus->bus);
}

#endif /* !_PCI_H_ */
