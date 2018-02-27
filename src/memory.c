#include <page.h>
#include <x86.h>

static inline pgd_t *kernel_pgd(void)
{
	return (pgd_t *)phys_to_virt(read_cr3() & PAGE_MASK);
}

static inline pud_t *kernel_pud(void)
{
	const pgd_t *pgd = kernel_pgd();
	const u64 off = pgd_offset(PAGE_OFFSET);
	return (pud_t *)phys_to_virt(pgd[off] & PAGE_MASK);
}

static pmd_t *kernel_pmd(void)
{
	const pud_t *pud = kernel_pud();
	const u64 off = pud_offset(PAGE_OFFSET);
	return (pmd_t *)phys_to_virt(pud[off] & PAGE_MASK);
}

static inline void map_frames(pmd_t *pmd, struct page_frame *f, u64 n, u32 flags)
{
	u64 frames_per_page = (2 * BIG_PAGE_SIZE) / PAGE_SIZE;
	for (u64 i = 0; i < n; ++i, f += frames_per_page) {
		pmd[i] = page_to_phys(f);
		pmd[i] |= flags;
	}
}

static inline void map_frame(pmd_t *pmd, struct page_frame *f, u32 flags)
{
	map_frames(pmd, f, 1, flags);
}

/*
 * Allocates pages in kernel space.
 *
 * XXX: ATM only 2MB pages are handled
 * TODO: add read-only and NX
 */
void *alloc_pages(u64 n)
{
	u64 off;
	pmd_t *pmd = kernel_pmd();

	for (off = 0; off < PTRS_PER_TABLE; ++off) {
		if (pg_present(pmd[off]))
			continue;
		u64 i;
		for (i = 1; i < n && off + i < PTRS_PER_TABLE; ++i)
			if (pg_present(pmd[off + i]))
				break;
		if (i != n)
			off = i + 1;
		else
			break;
	}
	if (off >= PTRS_PER_TABLE - n)
		return NULL;

	struct page_frame *f = alloc_page_frames(pmd + off, n * FRAMES_PER_2M_PAGE);
	if (f == NULL)
		return NULL;

	map_frames(pmd + off, f, n, PG_PRESENT|PG_WRITABLE|PG_HUGE_PAGE);
	return (void *)phys_to_virt(page_to_phys(f));
}

void *alloc_page(void)
{
	return alloc_pages(1);
}

void release_pages(void *p, u64 n)
{
	pmd_t *pmd = kernel_pmd();
	u64 off = pmd_offset((vaddr_t)p);

	for (u64 i = 0; i < n ; ++i, ++off) {
		pmd_t *entry = &pmd[off];
		struct page_frame *f = phys_to_page(*entry & PAGE_MASK);
		release_page_frames(f, FRAMES_PER_2M_PAGE);
		*entry &= ~PG_PRESENT;
	}
}

void release_page(void *p)
{
	release_pages(p, 1);
}
