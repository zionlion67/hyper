#ifndef _COMPILER_H_
#define _COMPILER_H_

#define __packed __attribute__((packed))

#define __align(va, sz) ((va) & ~(sz - 1))
#define __align_n(va, sz) (__align(va, sz) + sz)

#define NULL ((void *)0)

#endif
