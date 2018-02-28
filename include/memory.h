#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <types.h>

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
