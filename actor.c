/*
 *  actor.c
 *
 *  copyright (c) 2019, 2020 Xiongfei Shi
 *
 *  author: Xiongfei Shi <jenson.shixf(a)gmail.com>
 *  license: Apache-2.0
 *
 *  https://github.com/shixiongfei/actor
 */

#include <stdlib.h>
#include <string.h>

#include "actor.h"
#include "list.h"
#include "threads.h"

#define ACTOR_MAXMSG 1234567

static void *alloc_emul(void *ptr, size_t size) {
  if (size)
    return realloc(ptr, size);
  free(ptr);
  return NULL;
}

static void *(*actor_alloc)(void *, size_t) = alloc_emul;

void actor_setalloc(void *(*allocator)(void *, size_t)) {
  actor_alloc = allocator ? allocator : alloc_emul;
}

#define actor_malloc(size) actor_alloc(NULL, size)
#define actor_free(ptr) actor_alloc(ptr, 0)

typedef struct mailmsg_s {
  actormsg_t actor_msg;
  list_t mail_node;
  unsigned char buffer[1];
} mailmsg_t;

typedef struct actorwrap_s {
  int copied;
  void (*func)(void *);
  void *arg;
} actorwrap_t;

typedef struct actor_s {
  actorid_t actor_id;
  actorwrap_t wrap;

  list_t actor_node;
  list_t trash;
  list_t inbox[ACTOR_PRIORITIES];

  int payload[ACTOR_PRIORITIES];
  int stack[ACTOR_PRIORITIES];
  int stack_top;

  int msgsize;
  int maxsize;

  int r_waiting;
  int w_waiting;
  cond_t r_cond;
  cond_t w_cond;
  mutex_t mutex;
} actor_t;

static tls_t tls;
static list_t actor_list;
static mutex_t actor_mutex;

static int qstack_top(actor_t *actor) {
  if (actor->stack_top < 0)
    return -1;

  if (actor->stack_top >= ACTOR_PRIORITIES)
    return -1;

  return actor->stack[actor->stack_top];
}

static int qstack_push(actor_t *actor, int priority) {
  int top;

  if (priority < ACTOR_HIGH || priority > ACTOR_LOW)
    return -1;

  if (actor->stack_top + 1 >= ACTOR_PRIORITIES)
    return -1;

  top = qstack_top(actor);
  actor->stack[++actor->stack_top] = priority;

  return top;
}

static int qstack_pop(actor_t *actor) {
  int top;

  if (actor->stack_top < 0)
    return -1;

  top = qstack_top(actor);
  actor->stack[actor->stack_top--] = -1;

  return top;
}

void actor_initialize(void) {
  tls_create(&tls);
  list_init(&actor_list);
  mutex_create(&actor_mutex);
}

static actor_t *actor_create(void) {
  actor_t *actor = (actor_t *)actor_malloc(sizeof(actor_t));
  int i;

  if (!actor)
    return NULL;

  memset(actor, 0, sizeof(actor_t));

  mutex_create(&actor->mutex);
  cond_create(&actor->r_cond);
  cond_create(&actor->w_cond);

  list_init(&actor->actor_node);
  list_init(&actor->trash);

  for (i = 0; i < ACTOR_PRIORITIES; ++i) {
    list_init(&actor->inbox[i]);
    actor->stack[i] = -1;
  }

  actor->maxsize = ACTOR_MAXMSG;

  actor->stack_top = -1;
  qstack_push(actor, ACTOR_HIGH);

  return actor;
}

static void actor_push(actor_t *actor) {
  mutex_lock(&actor_mutex);
  list_push(&actor_list, &actor->actor_node);
  mutex_unlock(&actor_mutex);
}

static void actor_pop(actor_t *actor) {
  mutex_lock(&actor_mutex);
  list_erase(&actor->actor_node);
  mutex_unlock(&actor_mutex);
}

static void actor_destroy(actor_t *actor) {
  mailmsg_t *msg;
  list_t *p;
  int i;

  actor_pop(actor);

  mutex_lock(&actor->mutex);

  while (!list_empty(&actor->trash)) {
    p = list_shift(&actor->trash);
    msg = list_entry(p, mailmsg_t, mail_node);
    actor_free(msg);
  }

  for (i = 0; i < ACTOR_PRIORITIES; ++i)
    while (!list_empty(&actor->inbox[i])) {
      p = list_shift(&actor->inbox[i]);
      msg = list_entry(p, mailmsg_t, mail_node);
      actor_free(msg);
    }

  mutex_unlock(&actor->mutex);

  cond_destroy(&actor->w_cond);
  cond_destroy(&actor->r_cond);
  mutex_destroy(&actor->mutex);

  actor_free(actor);
}

void actor_finalize(void) {
  actor_t *actor;
  list_t *p, *t;

  mutex_lock(&actor_mutex);

  list_foreach(&actor_list, p, t) {
    actor = list_entry(p, actor_t, actor_node);
    actor_destroy(actor);
  }

  mutex_unlock(&actor_mutex);

  mutex_destroy(&actor_mutex);
  tls_destroy(tls);
}

#define actor_tryget() ((actor_t *)tls_getvalue(tls))

static actor_t *actor_current(void) {
  actor_t *actor = actor_tryget();

  if (!actor) {
    actor = actor_create();

    if (actor) {
      atom_set(&actor->actor_id, actor_gettid());
      tls_setvalue(tls, actor);
      actor_push(actor);
    }
  }

  return actor;
}

static actor_t *actor_query(actorid_t actor_id) {
  actor_t *finder, *actor = NULL;
  list_t *p, *t;

  mutex_lock(&actor_mutex);

  list_foreach(&actor_list, p, t) {
    finder = list_entry(p, actor_t, actor_node);

    if (actor_id == finder->actor_id) {
      actor = finder;
      break;
    }
  }

  mutex_unlock(&actor_mutex);

  return actor;
}

void actor_wrap(void (*func)(void *), void *arg) {
  actor_t *actor = actor_current();

  if (!actor->wrap.copied) {
    actor->wrap.func = func;
    actor->wrap.arg = arg;
    actor->wrap.copied = 1;
  }

  if (actor->wrap.func != func || actor->wrap.arg != arg)
    return;

  actor->wrap.func(actor->wrap.arg);

  tls_setvalue(tls, NULL);
  actor_destroy(actor);
}

static void actor_thread(void *arg) {
  actor_t *actor = actor_current();
  actorwrap_t *wrap = (actorwrap_t *)arg;

  actor->wrap = *wrap;
  actor->wrap.copied = 1;
  atom_set(&wrap->copied, 1);

  actor_wrap(actor->wrap.func, actor->wrap.arg);
}

actorid_t actor_spawn(void (*func)(void *), void *arg) {
  actorid_t actor_id = 0;
  actorwrap_t wrap = {0, func, arg};
  thread_t thread;
  int copied = 0;

  actor_id = thread_start(&thread, actor_thread, &wrap);
  thread_detach(&thread);

  do {
    atom_sync();
    atom_get(&wrap.copied, &copied);
  } while (!copied);

  return actor_id;
}

int actor_wait(actorid_t actor_id) {
  while (!!actor_query(actor_id))
    thread_sleep(10);
  return 0;
}

int actor_receive(actormsg_t *actor_msg, unsigned int timeout) {
  actor_t *actor = actor_current();
  list_t *node;
  mailmsg_t *msg;
  int top, retval = 1;

  if (!actor)
    return -1;

  mutex_lock(&actor->mutex);

  while (actor->msgsize == 0) {
    actor->r_waiting += 1;
    retval = cond_timedwait(&actor->r_cond, &actor->mutex, timeout);
    actor->r_waiting -= 1;

    if (retval < 1) {
      mutex_unlock(&actor->mutex);
      return retval;
    }
  }

  do {
    top = qstack_top(actor);
    actor->payload[top] += 1;

    if (top != ACTOR_HIGH)
      qstack_pop(actor);

    if ((actor->payload[top] & 1) == 0)
      qstack_push(actor, top + 1);
  } while (list_empty(&actor->inbox[top]));

  node = list_shift(&actor->inbox[top]);
  msg = list_entry(node, mailmsg_t, mail_node);
  actor->msgsize -= 1;

  if (actor_msg)
    *actor_msg = msg->actor_msg;

  list_push(&actor->trash, &msg->mail_node);

  if (actor->w_waiting > 0)
    cond_signal(&actor->w_cond);

  mutex_unlock(&actor->mutex);

  return retval;
}

static int actor_sendto(actor_t *actor, int priority, int type,
                        const void *data, int size) {
  actorid_t sender = actor_self();
  mailmsg_t *msg;

  if (sender < 0)
    return -1;

  msg = (mailmsg_t *)actor_malloc(sizeof(mailmsg_t) + size);

  if (!msg)
    return -1;

  if (priority < ACTOR_HIGH)
    priority = ACTOR_HIGH;

  if (priority > ACTOR_LOW)
    priority = ACTOR_LOW;

  list_init(&msg->mail_node);

  memcpy(msg->buffer, data, size);

  msg->actor_msg.receiver = actor->actor_id;
  msg->actor_msg.sender = sender;
  msg->actor_msg.priority = priority;
  msg->actor_msg.type = type;
  msg->actor_msg.data = msg->buffer;
  msg->actor_msg.size = size;

  mutex_lock(&actor->mutex);

  while (actor->msgsize == actor->maxsize) {
    actor->w_waiting += 1;
    cond_wait(&actor->w_cond, &actor->mutex);
    actor->w_waiting -= 1;
  }

  list_push(&actor->inbox[priority], &msg->mail_node);
  actor->msgsize += 1;

  if (actor->r_waiting > 0)
    cond_signal(&actor->r_cond);

  mutex_unlock(&actor->mutex);

  return 0;
}

int actor_send(actorid_t actor_id, int priority, int type, const void *data,
               int size) {
  actor_t *actor = actor_query(actor_id);

  if (!actor)
    return -1;

  if (!data)
    return -1;

  if (size <= 0)
    return -1;

  return actor_sendto(actor, priority, type, data, size);
}

int actor_reply(actormsg_t *msg, int priority, int type, const void *data,
                int size) {
  return actor_send(msg->sender, priority, type, data, size);
}

int actor_broadcast(int priority, int type, const void *data, int size) {
  actor_t *actor;
  list_t *p, *t;
  int counter = 0;

  mutex_lock(&actor_mutex);

  list_foreach(&actor_list, p, t) {
    actor = list_entry(p, actor_t, actor_node);

    if (0 == actor_sendto(actor, priority, type, data, size))
      counter += 1;
  }

  mutex_unlock(&actor_mutex);

  return counter;
}

actorid_t actor_self(void) {
  actor_t *actor = actor_tryget();

  if (!actor)
    return -1;

  return actor->actor_id;
}

void actor_garbagecollect(void) {
  actor_t *actor = actor_tryget();
  mailmsg_t *msg;
  list_t *p;

  if (!actor)
    return;

  mutex_lock(&actor->mutex);

  while (!list_empty(&actor->trash)) {
    p = list_shift(&actor->trash);
    msg = list_entry(p, mailmsg_t, mail_node);
    actor_free(msg);
  }

  mutex_unlock(&actor->mutex);
}
