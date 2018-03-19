#ifndef _PANIC_H_
#define _PANIC_H_

/* TODO real panic func */
#define panic(fmt, ...) 		\
({					\
	printf(fmt, ##__VA_ARGS__); 	\
	for (;;)			\
		asm volatile ("hlt");	\
})

#endif /* !_PANIC_H_ */
