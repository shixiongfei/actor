/*
 *  list.c
 *
 *  copyright (c) 2019, 2020 Xiongfei Shi
 *
 *  author: Xiongfei Shi <xiongfei.shi(a)icloud.com>
 *  license: Apache-2.0
 *
 *  https://github.com/shixiongfei/actor
 */

#include "list.h"

void list_unshift(list_t *list, list_t *node) {
  node->head = list;
  node->tail = list->tail;
  list->tail->head = node;
  list->tail = node;
}

void list_push(list_t *list, list_t *node) {
  node->tail = list;
  node->head = list->head;
  list->head->tail = node;
  list->head = node;
}

void list_erase(list_t *node) {
  node->head->tail = node->tail;
  node->tail->head = node->head;
  list_init(node);
}

void list_replace(list_t *old_node, list_t *new_node) {
  new_node->tail = old_node->tail;
  new_node->tail->head = new_node;
  new_node->head = old_node->head;
  new_node->head->tail = new_node;
  list_init(old_node);
}

void list_rotate(list_t *list) {
  list_t *n = list_shift(list);
  list_push(list, n);
}

list_t *list_shift(list_t *list) {
  list_t *n = list_first(list);
  list_erase(n);
  return n;
}

list_t *list_pop(list_t *list) {
  list_t *n = list_last(list);
  list_erase(n);
  return n;
}

int list_length(list_t *list) {
  list_t *p, *t;
  int counter = 0;

  list_foreach(list, p, t) counter += 1;

  return counter;
}
