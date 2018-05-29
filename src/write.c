#include <io.h>
#include <page_types.h>
#include <string.h>

static void serial_write(const char *s, u64 len)
{
	for (u64 i = 0; i < len; ++i)
		outb(0x3f8, s[i]);
}

struct screen {
	char	*fb;
	int	x;
	int	y;
	int	w;
	int	h;
	int	text_attr;
};

static inline void clear_screen(struct screen *screen)
{
	memset(screen->fb, 0, screen->w * screen->h * 2);
}

static void scroll(struct screen *screen, const u64 nb_lines)
{
	screen->x = 0;
	screen->y = screen->h - nb_lines;

	int screen_sz = screen->w * screen->h * 2;

	for (int i = nb_lines * screen->w * 2; i < screen_sz; ++i)
		screen->fb[i - nb_lines * screen->w * 2] = screen->fb[i];
	for (int i = screen_sz - nb_lines * screen->w * 2; i < screen_sz; ++i)
		screen->fb[i] = 0;
}

static void update_cursor(struct screen *screen)
{
	screen->x++;
	if (screen->x == screen->w) {
		screen->x = 0;
		screen->y++;
		if (screen->y == screen->h)
			scroll(screen, 1);
	}
}

static void screen_putc(struct screen *screen, const char c)
{
	switch (c) {
	case '\n':
		screen->x = screen->w - 1;
		update_cursor(screen);
		return;
	case '\r':
		screen->x = 0;
		return;
	case '\t':
		do
			screen_putc(screen, ' ');
		while (screen->x % 4);
		return;
	};

	const u64 pos = (screen->y * screen->w + screen->x) * 2;
	screen->fb[pos] = c;
	screen->fb[pos + 1] = screen->text_attr;

	update_cursor(screen);
}

#define TEXT_ATTR(back, front) (((back) << 4) | (front))

#define CONS_BLACK 0
#define CONS_WHITE 7
static struct screen vga_text = {
	.fb = (char *)0xb8000 + PHYS_MAP_START,
	.x = 0,
	.y = 0,
	.w = 80,
	.h = 25,
	.text_attr = TEXT_ATTR(CONS_BLACK, CONS_WHITE),
};

/* Does not handle console attributes */
static void screen_write(struct screen *screen, const char *s, u64 len)
{
	for (u64 i = 0; i < len; ++i)
		screen_putc(screen, s[i]);
}

void write(const char *s, u64 len)
{
	serial_write(s, len);
	screen_write(&vga_text, s, len);
}
