#ifndef _VM_IODEV_H_
#define _VM_IODEV_H_

#include "list.h"
#include "ept.h"

/* Inspired from KVM */

struct vmm;
struct vm_iodev;

struct vm_iodev_range {
	u16	start;
	u16	end;
	struct vm_iodev *iodev;
	struct list next;
};

struct vm_iodev_ops {
	int (*read)(struct vm_iodev *dev, gpa_t addr, u32 len, void *retval);
	int (*write)(struct vm_iodev *dev, gpa_t addr, u32 len, const void *val);
	int (*reset)(struct vm_iodev *dev);
};

struct vm_iodev {
	struct vmm *vmm;
	struct vm_iodev_ops *ops;
};

static inline int vm_iodev_read(struct vm_iodev *dev, u16 addr, u8 len,
				void *retval)
{
	return dev->ops->read(dev, addr, len, retval);
}

static inline int vm_iodev_write(struct vm_iodev *dev, u16 addr, u8 len,
				 const void *val)
{
	return dev->ops->write(dev, addr, len, val);
}

static inline int vm_iodev_reset(struct vm_iodev *dev)
{
	return dev->ops->reset(dev);
}


struct vm_iodev_bus;
struct vm_iodev_bus_ops {
	struct vm_iodev *(*has_emulator)(struct vm_iodev_bus *bus, u16 addr);
	int (*add_iodev)(struct vm_iodev_bus *bus, struct vm_iodev_range *range);
};

struct vm_iodev_bus {
	struct vm_iodev_bus_ops *ops;
	struct list dev_list;
};

static inline struct vm_iodev *vm_iodev_bus_has_emulator(struct vm_iodev_bus *bus,
							 u16 addr)
{
	return bus->ops->has_emulator(bus, addr);
}

static inline int vm_iodev_bus_add_iodev(struct vm_iodev_bus *bus,
					 struct vm_iodev_range *range)
{
	return bus->ops->add_iodev(bus, range);
}

#endif /* !_VM_IODEV_H_ */
