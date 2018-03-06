#include <page.h>
#include <stdio.h>

/*
 * Simple page frame allocator.
 */

static DECLARE_LIST(frame_free_list);

#define MAX_MEMORY_ZONES 20
static struct mem_zone memory_map[MAX_MEMORY_ZONES];
static u8 mem_zone_cnt = 0;

/* Start and End address of the frame array */
static struct page_frame *first_frame;
static struct page_frame *last_frame;
/* Physical address of the first frame */
static paddr_t first_frame_paddr;

/* Last valid page frame number */
u64 last_pfn;

/* Kernel start/end vaddr */
extern char _start[];
extern char _end[];

#define _2M_PAGE_SIZE	(2 * BIG_PAGE_SIZE)

/* ATM only get available regions */
static void init_memory_map(struct multiboot_tag_mmap *mmap)
{
	multiboot_memory_map_t *m = mmap->entries;
	u64 end = (u64)mmap + mmap->size;

	for (; (u64)m < end; m = ((u8 *)m + mmap->entry_size)) {
		struct mem_zone *zone = &memory_map[mem_zone_cnt];
		if (m->type != MULTIBOOT_MEMORY_AVAILABLE)
			continue;
		zone->start = m->addr;
		zone->length = m->len;
		zone->type = MEM_RAM_USABLE;

		if (zone->start + zone->length < BIG_PAGE_SIZE)
			zone->type |= MEM_LOW_MEM;

		mem_zone_cnt++;
	}
}

static paddr_t first_valid_paddr(void)
{
	paddr_t res = MAX_PHYS_ADDR;
	for (u8 i = 0; i < mem_zone_cnt; ++i) {
		struct mem_zone tmp = memory_map[i];
		if ((tmp.type & MEM_RAM_USABLE) && tmp.start < res)
			res = tmp.start;
	}
	return res;
}

static paddr_t last_valid_paddr(void)
{
	paddr_t res = 0;
	for (u8 i = 0; i < mem_zone_cnt; ++i) {
		struct mem_zone tmp = memory_map[i];
		if ((tmp.type & MEM_RAM_USABLE) && tmp.start + tmp.length > res)
			res = tmp.start + tmp.length;
	}
	return res;
}

static u8 paddr_mem_flags(paddr_t paddr)
{
	for (u8 i = 0; i < mem_zone_cnt; ++i) {
		struct mem_zone tmp = memory_map[i];
		if (paddr >= tmp.start && paddr < tmp.start + tmp.length)
			return tmp.type;
	}
	return MEM_RESERVED;
}

paddr_t page_to_phys(struct page_frame *frame)
{
	if (frame < first_frame || frame > last_frame)
		return (paddr_t)-1;
	paddr_t paddr = (paddr_t)(frame - first_frame);
	return (paddr << PAGE_SHIFT) + first_frame_paddr;
}

struct page_frame *phys_to_page(paddr_t addr)
{
	return &first_frame[(addr - first_frame_paddr) >> PAGE_SHIFT];
}

struct page_frame *pfn_to_page(u64 pfn)
{
	return first_frame + pfn;
}

static void set_frames_used(struct page_frame *start, struct page_frame *end,
			    vaddr_t vaddr)
{
	for (struct page_frame *tmp = start; tmp < end; ++tmp) {
		tmp->vaddr = vaddr;
		list_remove(&tmp->free_list);
		vaddr += PAGE_SIZE;
	}

}

#define PAGE_FRAME_ENTRY(l)	list_entry((l), struct page_frame, free_list)

/* Very dummy allocator */
/* Allocates n contiguous page frames */
struct page_frame *alloc_page_frames(vaddr_t vaddr, u64 nb_frame)
{
	struct list *l;
	list_for_each_reverse(&frame_free_list, l) {
		struct page_frame *start = PAGE_FRAME_ENTRY(l);
		struct page_frame *end;
		u64 n = nb_frame;
		for (end = start; end < last_frame && n > 0; ++end, --n) {
			/* frame isn't free */
			if (list_empty(&end->free_list))
				break;
		}
		if (n > 0)
			continue;
		/* we found contigous frames */
		set_frames_used(start, end, vaddr);
		return start;
	}
	return NULL;
}

void release_page_frames(struct page_frame *f, u64 n)
{
	for (u64 i = 0; i < n; ++i) {
		f[i].vaddr = (vaddr_t)NULL;
		list_add(&frame_free_list, &f[i].free_list);
	}
}


/* Build page frame array and init free frames list */
int memory_init(struct multiboot_tag_mmap *mmap)
{
	init_memory_map(mmap);

	paddr_t first_paddr = first_valid_paddr();
	paddr_t last_paddr = last_valid_paddr();
	first_frame_paddr = first_paddr;

	/* number of 4K frames */
	u64 frame_count = (last_paddr - first_paddr) / PAGE_SIZE;

	/* the frame array is located just after the kernel */
	first_frame = (void *)_end;
	last_frame = first_frame + frame_count;

	pmd_t *pmd = kernel_pmd();
	u64 cnt;
	for (cnt = 0; cnt < PTRS_PER_TABLE - 1; ++cnt) {
		if (!pg_present(pmd[cnt + 1]))
			break;
		continue;
	}

	paddr_t end = (pmd[cnt] & PAGE_MASK) + _2M_PAGE_SIZE;
	u64 last_frame_off = pmd_offset((vaddr_t)last_frame);
	if (cnt > last_frame_off)
		last_frame_off = cnt + 1;
	paddr_t reserved_end = end + (last_frame_off - cnt) * _2M_PAGE_SIZE;

	cnt = 0;
	for (struct page_frame *f = first_frame; f < last_frame; ++f) {
		/* check if frame is on two different page */
		u64 pmd_off = pmd_offset((vaddr_t)f + sizeof(struct page_frame));
		if (!pg_present(pmd[pmd_off])) {
			pmd_t new = pmd[pmd_off - 1] + _2M_PAGE_SIZE;
			pmd[pmd_off] = new & ~(PG_ACCESSED|PG_DIRTY);
		}

		const paddr_t paddr = page_to_phys(f);
		list_init(&f->free_list);
		if (!(paddr_mem_flags(paddr) & MEM_RAM_USABLE))
			continue;

		f->vaddr = (vaddr_t)NULL;
		/* don't add physical memory used by kernel and frame array */
		if (paddr < virt_to_phys(_start) || paddr >= reserved_end)
			list_add(&frame_free_list, &f->free_list);
		cnt++;
	}
	last_pfn = cnt - 1;
	return 0;
}
