/*
 *  list.h
 *
 *  copyright (c) 2019 Xiongfei Shi
 *
 *  author: Xiongfei Shi <jenson.shixf(a)gmail.com>
 *  license: Apache2.0
 *
 *  https://github.com/shixiongfei/actor
 */

#ifndef __LIST_H__
#define __LIST_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct list_s list_t;

struct list_s {
  list_t *head;
  list_t *tail;
};

#define list_entry(ptr, type, member)                                          \
  ((type *)((char *)(ptr)-offsetof(type, member)))

#define LIST_INIT(l)                                                           \
  { &(l), &(l) }

#define list_init(l)                                                           \
  do {                                                                         \
    (l)->head = (l);                                                           \
    (l)->tail = (l);                                                           \
  } while (0)

void list_unshift(list_t *list, list_t *node);
void list_push(list_t *list, list_t *node);
void list_erase(list_t *node);
void list_replace(list_t *old_node, list_t *new_node);
void list_rotate(list_t *list);

list_t *list_shift(list_t *list);
list_t *list_pop(list_t *list);

int list_length(list_t *list);

#define list_head(n) ((n)->head)
#define list_tail(n) ((n)->tail)
#define list_first(l) list_tail(l)
#define list_last(l) list_head(l)
#define list_prev(n) list_head(n)
#define list_next(n) list_tail(n)
#define list_isempty(l)                                                        \
  (((l) == list_head(l)) && (list_head(l) == list_tail(l)))

#define list_foreach(l, p, t)                                                  \
  for ((p) = list_first(l), (t) = list_next(p); (l) != (p);                    \
       (p) = (t), (t) = list_next(p))

#define list_foreachreverse(l, p, t)                                           \
  for ((p) = list_last(l), (t) = list_prev(p); (l) != (p);                     \
       (p) = (t), (t) = list_prev(p))

#ifdef __cplusplus
};
#endif

#endif /* __LIST_H__ */
