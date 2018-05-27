#include <compiler.h>
#include <page.h>
#include <stdio.h>

static DECLARE_LIST(frame_free_list);

#define MAX_MEMORY_ZONES 20
struct memory_map {
	struct mem_zone zones[MAX_MEMORY_ZONES];
	u8 zone_cnt;
};

static struct memory_map memory_map = {
	.zone_cnt = 0,
};

struct frame_state {
	struct page_frame *begin;	/* Start of the frame array */
	struct page_frame *end;		/* End of the frame array */
	u64 last_pfn;			/* Last valid page frame number */
};

static struct frame_state frame_state;

/* Kernel start */
extern char _start[];

#define LOW_MEM_END 	(1 << 20)
#define _2M_PAGE_SIZE	(2 * BIG_PAGE_SIZE)

/* ATM only get available regions */
static void init_memory_map(struct multiboot_tag_mmap *mmap)
{
	multiboot_memory_map_t *m = mmap->entries;
	u64 end = (u64)mmap + mmap->size;

	for (; (u64)m < end; m = (void *)((u8 *)m + mmap->entry_size)) {
		struct mem_zone *zone = &memory_map.zones[memory_map.zone_cnt];
		if (m->type != MULTIBOOT_MEMORY_AVAILABLE)
			continue;
		zone->start = m->addr;
		zone->length = m->len;
		zone->type = MEM_RAM_USABLE;

		if (zone->start + zone->length < LOW_MEM_END)
			zone->type |= MEM_LOW_MEM;

		memory_map.zone_cnt++;
	}
}

static inline int mem_is_usable(const u8 type)
{
	return type & MEM_RAM_USABLE;
}

static paddr_t first_valid_paddr(void)
{
	paddr_t res = MAX_PHYS_ADDR;
	for (u8 i = 0; i < memory_map.zone_cnt; ++i) {
		const struct mem_zone *tmp = &memory_map.zones[i];
		if (mem_is_usable(tmp->type) && tmp->start < res)
			res = tmp->start;
	}
	return res;
}

static paddr_t last_valid_paddr(void)
{
	paddr_t res = 0;
	for (u8 i = 0; i < memory_map.zone_cnt; ++i) {
		const struct mem_zone *tmp = &memory_map.zones[i];
		if (mem_is_usable(tmp->type) && tmp->start + tmp->length > res)
			res = tmp->start + tmp->length;
	}
	return res;
}

static u8 paddr_mem_type(paddr_t paddr)
{
	for (u8 i = 0; i < memory_map.zone_cnt; ++i) {
		const struct mem_zone *tmp = &memory_map.zones[i];
		if (paddr >= tmp->start && paddr < tmp->start + tmp->length)
			return tmp->type;
	}
	return MEM_RESERVED;
}

/* Setup 4G physical memory map starting from virtual addr PHYS_MAP_START */
static void setup_phys_map(void)
{
	pud_t *pud = kernel_pud();
	for (vaddr_t va = PHYS_MAP_START; va < PHYS_MAP_END; va += (1 << 30))
		pud[pud_offset(va)] = pte_rw_huge(virt_to_phys(va));
}

static void init_frame_state(struct frame_state *state, vaddr_t mod_end)
{
	const paddr_t first_paddr = __align(first_valid_paddr(), PAGE_SIZE);
	const paddr_t last_paddr = __align(last_valid_paddr(), PAGE_SIZE);
	const u64 nb_frames = (last_paddr - first_paddr) / PAGE_SIZE;

	/* Use PHYS_MAP mapping for the frame array */
	state->begin = (struct page_frame *)phys_to_virt(virt_to_phys(mod_end));
	state->end = state->begin + nb_frames;
	state->last_pfn = nb_frames - 1;
}

paddr_t page_to_phys(const struct page_frame *frame)
{
	return (frame - frame_state.begin) << PAGE_SHIFT;
}

struct page_frame *phys_to_page(const paddr_t paddr)
{
	return frame_state.begin + (paddr >> PAGE_SHIFT);
}

static inline void init_page_frame(struct page_frame *f)
{
	list_init(&f->free_list);
	f->vaddr = (vaddr_t)NULL;
}

static inline int paddr_is_reserved(const paddr_t paddr)
{
	return (paddr >= virt_to_phys(_start)
		&& paddr < virt_to_phys(frame_state.end));
}

static void setup_frame_state(vaddr_t mod_end)
{
	struct frame_state *state = &frame_state;
	init_frame_state(state, mod_end);

	for (struct page_frame *f = state->begin; f < state->end; ++f) {
		init_page_frame(f);
		const paddr_t paddr = page_to_phys(f);
		if (!mem_is_usable(paddr_mem_type(paddr)))
			continue;
		if (!paddr_is_reserved(paddr))
			list_add(&frame_free_list, &f->free_list);
	}
}

#define PAGE_FRAME_ENTRY(l)	list_entry((l), struct page_frame, free_list)
/* Very dummy allocator */
/* Try to allocates `nb_frames` contiguous frames */
struct page_frame *alloc_page_frames(u64 nb_frames)
{
	struct list *l;
	list_for_each_reverse(&frame_free_list, l) {
		struct page_frame *start = PAGE_FRAME_ENTRY(l);
		struct page_frame *end;
		u64 n = nb_frames;
		for (end = start; end < frame_state.end && n > 0; ++end, --n)
			if (list_empty(&end->free_list))
				break;
		/* No contigous frames found */
		if (n > 0)
			continue;

		/* Remove frames from free list */
		for (struct page_frame *f = start; f < end; ++f)
			list_remove(&f->free_list);

		return start;
	}
	return NULL;
}

void release_page_frames(struct page_frame *f, u64 n)
{
	for (u64 i = 0; i < n; ++i)
		list_add(&frame_free_list, &f[i].free_list);
}

int memory_init(struct multiboot_tag_mmap *mmap, vaddr_t mod_end)
{
	init_memory_map(mmap);
	setup_phys_map();
	setup_frame_state(mod_end);

	return 0;
}
