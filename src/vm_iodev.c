#include <vmx.h>
#include <kmalloc.h>

#define IODEV_BUS_LIST_ENTRY(l)	list_entry((l), struct vm_iodev_bus_list, next)
static struct vm_iodev *has_emulator(struct vm_iodev_bus *bus, gpa_t addr)
{
	struct list *iodev_list;
	list_for_each(&bus->dev_list, iodev_list) {
		struct vm_iodev_bus_list *list = IODEV_BUS_LIST_ENTRY(iodev_list);
		if (list->range->start <= addr && addr <= list->range->end)
			return list->range->iodev;
	}
	return NULL;
}

/* TODO sorted instertion so we can lookup faster on emulated devices */
static int add_iodev(struct vm_iodev_bus *bus, struct vm_iodev_range *range)
{
	struct vm_iodev_bus_list *l = kmalloc(sizeof(struct vm_iodev_bus_list));
	if (l == NULL)
		return 1;
	l->range = range;
	list_add(&bus->dev_list, &l->next);
	return 0;
}

static int iodev_bus_init(struct vm_iodev_bus *bus)
{
	(void)bus;
	return 0;
}

static struct vm_iodev_bus_ops default_iodev_bus_ops = {
	.has_emulator = has_emulator,
	.add_iodev = add_iodev,
};

struct vm_iodev_bus *alloc_init_iodev_bus_ops(struct vm_iodev_bus_ops *ops)
{
	struct vm_iodev_bus *bus = kmalloc(sizeof(struct vm_iodev_bus));
	if (bus == NULL)
		return 1;

	bus->ops = ops;
	list_init(&bus->dev_list);

	if (iodev_bus_init(bus)) {
		kfree(bus);
		return 1;
	}
	return bus;
}

struct vm_iodev_bus *alloc_init_iodev_bus(void)
{
	return alloc_init_iodev_bus_ops(&default_iodev_bus_ops);
}
