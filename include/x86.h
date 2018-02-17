#ifndef _X86_H_
#define _X86_H_

#define CR4_PAE_BIT 		5
#define CR4_PAE 		(1 << CR4_PAE_BIT)

#define CR0_PE_BIT		0
#define CR0_PG_BIT		31

#define CR0_PE			(1 << CR0_PE_BIT)
#define CR0_PG			(1 << CR0_PG_BIT)

#define MSR_EFER		0xc0000080 /* Extended Features Register */
#define MSR_EFER_LME_BIT	8
#define MSR_EFER_LME		(1 << MSR_EFER_LME_BIT)

#endif
