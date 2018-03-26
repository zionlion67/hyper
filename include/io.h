#ifndef IO_H_
#define IO_H_

#include <types.h>

static inline void outb(u16 port, u8 val)
{
	asm volatile ("outb %0, %1" : /* No output */ : "a"(val), "d"(port));
}

static inline void outw(u16 port, u16 val)
{
	asm volatile ("outw %0, %1" : /* No output */ : "a"(val), "d"(port));
}


static inline void outl(u16 port, u32 val)
{
	asm volatile ("outl %0, %1" : /* No output */ : "a"(val), "d"(port));
}

static inline u8 inb(u16 port)
{
	u8 res;
	asm volatile ("inb %1, %0" : "=&a"(res) : "d"(port));
	return res;
}

static inline u16 inw(u16 port)
{
	u16 res;
	asm volatile ("inw %1, %0" : "=&a"(res) : "d"(port));
	return res;
}

static inline u32 inl(u16 port)
{
	u32 res;
	asm volatile ("inl %1, %0" : "=&a"(res) : "d"(port));
	return res;
}

#endif
