#include <compiler.h>
#include <panic.h>
#include <stdio.h>
#include <types.h>
#include <vmx.h>

struct uart_8250 {
	u8  thr;      /* Transmitter Holding Buffer */
	u8  rbr;      /* Receiver buffer */
	u8  dll;      /* Divisor Latch Low Byte */
	u8  ier;      /* Interrupt Enable Register */
	u8  dlh;      /* Divisor Latch High Byte */
	u8  iir;      /* Interrupt Identification register */
	u8  fcr;      /* FIFO Control register */
	u8  lcr;      /* Line Control Register */
	u8  mcr;      /* Modem Control Register */
	u8  lsr;      /* Line Status Register */
	u8  msr;      /* Modem Status Register */
	u8  sr;       /* Scratch Register */
	u16 io_base;
} __packed;

#define UART_COM1		0x3f8
#define UART_IIR_EMPTY_BUF	(3 << 6)
#define UART_LCR_DLAB		(1 << 7)
#define UART_LSR_EMPTY_REG	(3 << 5)

static struct uart_8250 uart_state;

/*
 * Here's the 'serial2vga' hack:
 * To test bare-metal without having physical serial, boot linux
 * with console=ttyS0 + trap on serial writes + display on text VGA.
 * This way, we can see if the guest boots when we're bare metal.
 */
static void emulate_uart_8250_write(u8 val, u16 port)
{
	struct uart_8250 *uart = &uart_state;
	switch (port & 7) {
	case 0:
		if (uart->lcr & UART_LCR_DLAB) {
			uart->dll = val;
		} else {
			uart->thr = val;
			printf("%c", val);
		}
		return;
	case 1:
		if (uart->lcr & UART_LCR_DLAB)
			uart->dlh = val;
		else
			uart->ier = val;
		return;
	case 2:
		uart->fcr = val;
		return;
	case 3:
		uart->lcr = val;
		return;
	case 4:
		uart->mcr = val;
		return;
	case 7:
		uart->sr = val;
		/* fallthrough */
	default:
		return;
	}
}

static u8 emulate_uart_8250_read(u16 port)
{
	static char last_char = 0;
	struct uart_8250 *uart = &uart_state;

	switch (port & 7) {
	case 0:
		return last_char;
	case 1:
		if (uart->lcr & UART_LCR_DLAB)
			return uart->dlh;
		else
			return uart->ier & ~(3 << 6);
	case 2:
		return uart->iir & ~UART_IIR_EMPTY_BUF;
	case 3:
		return uart->lcr;
	case 4:
		return uart->mcr;
	case 5:
		if (last_char)
			uart->lsr |= 1;
		else
			uart->lsr &= ~1;
		return uart->lsr | UART_LSR_EMPTY_REG;
	case 6:
		return uart->msr;
	case 7:
		return 0;
	}

	__builtin_unreachable();
}

void emulate_uart_8250(struct x86_regs *regs, struct io_access_info *info)
{
	if (info->access_sz != 0) {
		printf("Unhandled serial access size: %d\n", info->access_sz);
		printf("Direction: %s\n", info->in ? "in" : "out");
		panic("");
	}

	if (!info->in)
		emulate_uart_8250_write(regs->rax & 0xff, info->port);
	else
		regs->rax = emulate_uart_8250_read(info->port);
}
