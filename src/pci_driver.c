#include <pci.h>
#include <drivers/ahci.h>

/*
 * Nothing is modular, too lazy to implement kernel modules atm,
 * so register all PCI drivers here.
 */

static DECLARE_LIST(pci_drivers);

typedef struct pci_driver *(*register_routine_t)(void);

/* These functions returns a pointer to the pci_driver to be registered */
static const register_routine_t register_routines[] = {
	register_ahci,
};

/* We might want to return a status later. */
int pci_register_driver(struct pci_driver *driver)
{
	list_add(&pci_drivers, &driver->next);
	return 0;
}

int pci_register_drivers(void)
{
	int err = 0;
	for (u16 i = 0; i < array_size(register_routines); ++i) {
		struct pci_driver *drv = register_routines[i]();
		err += pci_register_driver(drv);
	}
	return err;
}

#define PCI_DRV_ENTRY(l) list_entry((l), struct pci_driver, next)
struct pci_driver *pci_find_driver(struct pci_device_id *id)
{
	struct list *l;
	list_for_each(&pci_drivers, l) {
		struct pci_driver *drv = PCI_DRV_ENTRY(l);
		/* TODO loop on driver id table (make it null term) */
		if (pci_id_match(drv->id, id))
			return drv;
	}

	return NULL;
}
