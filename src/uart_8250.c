#include <compiler.h>
#include <panic.h>
#include <stdio.h>
#include <types.h>
#include <vmx.h>

struct uart_8250 {
	struct vm_iodev iodev;
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

#define to_uart_8250(Iodev)	container_of(Iodev, struct uart_8250, iodev)

/*
 * Here's the 'serial2vga' hack:
 * To test bare-metal without having physical serial, boot linux
 * with console=ttyS0 + trap on serial writes + display on text VGA.
 * This way, we can see if the guest boots when we're bare metal.
 */
static void emulate_uart_8250_write(struct uart_8250 *uart, u8 val, u16 port)
{
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

static u8 emulate_uart_8250_read(struct uart_8250 *uart, u16 port)
{
	static char last_char = 0;

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

static int uart_8250_read(struct vm_iodev *dev, gpa_t addr, u32 len,
			  void *retval)
{
	if (len != 1)
		panic("Unhandled i/o read access size: %u\n", len);

	struct uart_8250 *uart_state = to_uart_8250(dev);
	*(u8 *)retval = emulate_uart_8250_read(uart_state, addr & 0xffff);
	return 0;
}

static int uart_8250_write(struct vm_iodev *dev, gpa_t addr, u32 len,
			   const void *val)
{
	if (len != 1)
		panic("Unhandled i/o write access size: %u\n", len);

	struct uart_8250 *uart_state = to_uart_8250(dev);
	emulate_uart_8250_write(uart_state, *(u8 *)val, addr & 0xffff);
	return 0;

}

static struct vm_iodev_ops uart_8250_iodev_ops = {
	.read = uart_8250_read,
	.write = uart_8250_write,
};

static struct uart_8250 uart_state = {
	.iodev = {
		.ops = &uart_8250_iodev_ops,
	},
};

VM_IODEVICE(uart, 0x3f8, 0x3ff, &uart_state.iodev);
