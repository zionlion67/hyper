#ifndef _COMPILER_H_
#define _COMPILER_H_

#define __packed 	__attribute__((packed))
#define __unused 	__attribute__((unused))
#define __maybe_unused 	__unused
#define __used		__attribute__((used))

#define __align(va, sz) ((va) & ~(sz - 1))
#define __align_n(va, sz) (__align(va, sz) + sz)

#define array_size(array) (sizeof(array) / sizeof(*array))

#define NULL ((void *)0)

#ifndef offsetof
#define offsetof(type, field) \
	((unsigned long)(&((type *)0)->field))
#endif

#define container_of(addr, type, field) \
	((type *)((char *)addr - offsetof(type, field)))

#define ERR_PTR(x) ((void *)x)

#endif
