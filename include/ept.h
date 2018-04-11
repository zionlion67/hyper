#ifndef _EPT_H_
#define _EPT_H_

#include "page_types.h"

/* TODO potentially factorize these */

#define EPT_PTRS_PER_TABLE	512
struct eptp {
	union {
		struct {
			u64	type : 3;
			u64	page_walk_length : 3;
			u64	enable_dirty_flag : 1;
			u64	pad0 : 5;
			u64	pml4_addr : 36;
			u64	pad1 : 16;
		};
		u64	quad_word;
	};
};

struct ept_pml4e {
	union {
		struct {
			u64	read : 1;
			u64	write : 1;
			u64	kern_exec : 1;
			u64	pad0 : 5;
			u64	dirty : 1;
			u64	pad1 : 1;
			u64	user_exec : 1;
			u64	pad2 : 1;
			u64	paddr : 36;
			u64	pad3 : 16;
		};
		u64	quad_word;
	};
};

struct ept_huge_pdpte {
	union {
		struct {
			u64	read : 1;
			u64	write : 1;
			u64	kern_exec : 1;
			u64	memory_type : 3;
			u64	ignore_pat : 1;
			u64	huge_page : 1;
			u64	accessed : 1;
			u64	dirty : 1;
			u64	user_exec : 1;
			u64	pad0 : 19;
			u64	paddr : 18;
			u64	pad1 : 15;
			u64	suppress_ve : 1;
		};
		u64	quad_word;
	};
};

struct ept_pdpte {
	union {
		struct {
			u64	read : 1;
			u64	write : 1;
			u64	kern_exec : 1;
			u64	pad0 : 5;
			u64	accessed : 1;
			u64	pad1 : 1;
			u64	user_exec : 1;
			u64	pad2 : 1;
			u64	paddr : 36;
			u64	pad3 : 16;
		};
		u64	quad_word;
	};
};

struct ept_huge_pde {
	union {
		struct {
			u64	read : 1;
			u64	write : 1;
			u64	kern_exec : 1;
			u64	memory_type : 3;
			u64	ignore_pat : 1;
			u64	huge_page : 1;
			u64	accessed : 1;
			u64	dirty : 1;
			u64	user_exec : 1;
			u64	pad0 : 10;
			u64	paddr : 27;
			u64	pad1 : 15;
			u64	suppress_ve : 1;
		};
		u64	quad_word;
	};
};

struct ept_pde {
	union {
		struct {
			u64	read : 1;
			u64	write : 1;
			u64	kern_exec : 1;
			u64	reserved1 : 4;
			u64	zero1 : 1;
			u64	accessed : 1;
			u64	reserved2 : 1;
			u64	user_exec : 1;
			u64	reserved3 : 1;
			u64	paddr : 36;
			u64	reserved4 : 16;
		};
		u64	quad_word;
	};
};

struct ept_pte {
	union {
		struct {
			u64	read : 1;
			u64	write : 1;
			u64	kern_exec : 1;
			u64	memory_type : 3;
			u64	ignore_pat : 1;
			u64	reserved1 : 1;
			u64	accessed : 1;
			u64	dirty : 1;
			u64	user_exec : 1;
			u64	reserved2 : 1;
			u64	paddr : 36;
			u64	reserved3 : 16;
		};
		u64	quad_word;
	};
};

paddr_t ept_translate(struct eptp *eptp, paddr_t addr);

#endif
