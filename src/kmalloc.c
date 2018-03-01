#include <page.h>
#include <memory.h>

#define ARENA_SIZE ALLOC_PAGE_SIZE

#define CHUNK_SIZE(sz) (sz + sizeof(struct mem_chunk))

struct mem_arena {
	void *max_brk;
	void *cur_brk;
	struct list next_arena;
	struct list free_chunks;
	char data[0];
};

struct mem_chunk {
	u64 size;
	struct list free_chunks;
};

static DECLARE_LIST(arena_list);

static inline int arena_can_allocate(struct mem_arena *a, u64 sz)
{
	return ((vaddr_t)a->cur_brk + CHUNK_SIZE(sz) < (vaddr_t)a->max_brk);
}

static struct mem_chunk *find_free_chunk(struct mem_arena *arena, u64 size)
{
	if (list_empty(&arena->free_chunks))
		return NULL;

	struct mem_chunk *cur_chunk;
	list_for_each_entry(&arena->free_chunks, cur_chunk, free_chunks) {
		if (cur_chunk->size >= size)
			break;
	}

	/* we found a free chunk that has enough space */
	if ((vaddr_t)&cur_chunk->free_chunks != (vaddr_t)&arena->free_chunks
	    && cur_chunk->size >= size) {
		list_remove(&cur_chunk->free_chunks);
		return cur_chunk;
	}

	return NULL;
}

void *kmalloc(u64 size)
{
	if (__align(size, 8) != size)
		size = __align_n(size, 8);

	struct mem_arena *arena;
	list_for_each_entry(&arena_list, arena, next_arena) {
		struct mem_chunk *chunk = find_free_chunk(arena, size);
		if (chunk != NULL)
			return (void *)(chunk + 1);
		/*
		 * No free chunk in this arena, check if we can
		 * allocate a new chunk
		 */
		if (!arena_can_allocate(arena, size))
			continue;

		/* We can allocate a new chunk in this arena */
		chunk = arena->cur_brk;
		chunk->size = size;
		list_init(&chunk->free_chunks);
		arena->cur_brk = (vaddr_t)arena->cur_brk + CHUNK_SIZE(size);
		return (void *)(chunk + 1);
	}

	/* We found no available memory on existing arenas */
	/* TODO allocate new arena, if this fails, panic */
	return NULL;

}

//TODO implement me !
void kfree(void *p)
{
	(void)p;
}

int init_kmalloc(void)
{
	struct mem_arena *first_arena = alloc_page();
	if (first_arena == NULL)
		return 1;
	first_arena->max_brk = (vaddr_t)first_arena + ARENA_SIZE;
	first_arena->cur_brk = first_arena->data;
	list_init(&first_arena->next_arena);
	list_init(&first_arena->free_chunks);
	list_add(&arena_list, &first_arena->next_arena);
	return 0;
}
