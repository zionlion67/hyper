#ifndef _DEVICE_H_
#define _DEVICE_H_

#include "list.h"

/*
 * This header defines basic interfaces, they should
 * not be used alone but specialized in other structs.
 */


/* Assume buses are discoverable */
struct bus;
struct bus_ops {
	int (*discover)(struct bus *);
};

struct bus {
	const char	 	*name;
	const struct bus_ops	*bus_ops;
	struct list		devices;
};

static inline int bus_init(struct bus *bus, const char *name,
			   const struct bus_ops *ops)
{
	bus->name = name;
	bus->bus_ops = ops;
	list_init(&bus->devices);

	return ops->discover(bus);
}

struct device;
struct device_driver_ops {
	int (*probe)(struct device *dev);
	/* Add other ops here, shutdown(), reset(), ... */
};

struct device_driver {
	const char *name;
	const struct device_driver_ops *ops;
};

struct device {
	const char 		*desc;
	struct bus		*bus;
	struct device_driver 	*drv;
};


#endif /* !_DEVICE_H_ */
