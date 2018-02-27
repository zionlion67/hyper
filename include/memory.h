#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <types.h>

void *alloc_pages(u64 n);
void *alloc_page(void);

void release_pages(void *p, u64 n);
void release_page(void *p);

#endif /* !_MEMORY_H_ */
