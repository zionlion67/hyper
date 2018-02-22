#ifndef _PAGE_TYPES_H_
#define _PAGE_TYPES_H_

#include <types.h>

typedef u64 paddr_t;
typedef u64 vaddr_t;

typedef u64 pgd_t;
typedef u64 pud_t;
typedef u64 pmd_t;
typedef u64 pte_t;

#define PG_PRESENT		(1 << 0)
#define PG_WRITABLE		(1 << 1)
#define PG_USER			(1 << 2)
#define PG_WRITE_THROUGH	(1 << 3)
#define PG_NO_CACHE		(1 << 4)
#define PG_ACCESSED		(1 << 5)
#define PG_DIRTY		(1 << 6)
#define PG_HUGE_PAGE		(1 << 7)
#define PG_GLOBAL		(1 << 8)
#define PG_NO_EXECUTE		(1 << 63)

#define PAGE_SHIFT	12
#define PAGE_SIZE	(1UL << PAGE_SHIFT) 
#define PAGE_MASK	(~(PAGE_SIZE - 1))

#define BIG_PAGE_SHIFT	20
#define BIG_PAGE_SIZE	(1UL << BIG_PAGE_SHIFT)
#define BIG_PAGE_MASK	(~(BIG_PAGE_SIZE - 1))

#define PGDIR_SHIFT	39
#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE - 1))

#define PUD_SHIFT	20
#define PUD_SIZE	(1UL << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE - 1))

#define PMD_SHIFT	21
#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE - 1))

#define PTRS_PER_TABLE	512

#define MAX_PHYS_ADDR	(0xffffffffffffffffUL)

#endif /* !_PAGE_TYPES_H */
