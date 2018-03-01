#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <types.h>
#include <page_types.h>

#define ALLOC_PAGE_SIZE	(2 * BIG_PAGE_SIZE)

void *alloc_pages(u64 n);
void release_pages(void *p, u64 n);

static inline void *alloc_page(void)
{
	return alloc_pages(1);
}

static inline void release_page(void *p)
{
	release_pages(p, 1);
}

#endif /* !_MEMORY_H_ */
