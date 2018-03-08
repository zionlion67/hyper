#ifndef _ASM_H_
#define _ASM_H_

#define __ASM__

#define ASM_NL ;

#define ASM_ALIGN .align 8

#define PROC_ENTRY(name)    \
	.global name ASM_NL \
	ASM_ALIGN ASM_NL    \
	name:

#define ASM_SYM_SIZE(name)    \
	.size name, . - name \

#define PROC_END(name) 		     \
	.type name, @function ASM_NL \
	ASM_SYM_SIZE(name)

#endif /*!_ASM_H_*/
