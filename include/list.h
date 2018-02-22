#ifndef _LIST_H_
#define _LIST_H_

#include <compiler.h>

struct list {
	struct list *next;
	struct list *prev;
};

#define LIST_INIT(name) { &(name), &(name) }

#define DECLARE_LIST(name) \
	struct list name = LIST_INIT(name)

static inline void list_init(struct list *head)
{
	if (!head)
		return;
	head->next = head;
	head->prev = head;
}

static inline void list_add(struct list *head, struct list *new)
{
	if (!head || !new)
		return;

	new->next = head->next;
	new->prev = head;
	head->next->prev = new;
	head->next = new;
}

static inline void list_remove(struct list *elt)
{
	if (!elt || !elt->prev || !elt->next)	
		return;
	elt->next->prev = elt->prev;
	elt->prev->next = elt->next;
	elt->next = NULL;
	elt->prev = NULL;
}

#define list_entry(elt, type, field)	container_of(elt, type, field)

#define list_for_each(head, elm) 					\
	for (elm = (head)->next; elm != head; elm = (elm)->next)

#define list_for_each_reverse(head, elm) 				\
	for (elm = (head)->prev; elm != head; elm = (elm)->prev)

#define __list_for_each(head, elm, field, dir)				\
	for (elm = list_entry((head)->dir, typeof(*elm), field);	\
	     &elm->field != head;					\
	     elm = list_entry(elm->field.dir, typeof(*elm), field))

#define list_for_each_entry(head, elm, field)				\
	__list_for_each(head, elm, field, next)

#define list_for_each_entry_reverse(head, elm, field)			\
	__list_for_each(head, elm, field, prev)

#endif /* !_LIST_H_ */
