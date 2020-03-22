/*
 *  actor.c
 *
 *  copyright (c) 2019 Xiongfei Shi
 *
 *  author: Xiongfei Shi <jenson.shixf(a)gmail.com>
 *  license: Apache-2.0
 *
 *  https://github.com/shixiongfei/actor
 */

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "list.h"

allocator_t allocator = {malloc, free};

void actor_setalloc(void *(*alloc)(size_t), void (*release)(void *)) {
  allocator.alloc = alloc ? alloc : malloc;
  allocator.release = release ? release : free;
}

typedef struct mailmsg_s {
  actormsg_t actor_msg;
  list_t mail_node;
  unsigned char buffer[1];
} mailmsg_t;

typedef struct actorwrap_s {
  void (*func)(void *);
  void *arg;
} actorwrap_t;

typedef struct actor_s {
  actorid_t actor_id;

  int waiting;

  list_t actor_node;
  list_t inbox;
  list_t trash;

  mutex_t mutex;
  cond_t wait_cond;
} actor_t;

static tls_t tls;
static list_t actor_list;
static mutex_t actor_mutex;

void actor_initialize(void) {
  tls_create(&tls);
  list_init(&actor_list);
  mutex_create(&actor_mutex);
}

static actor_t *actor_create(void) {
  actor_t *actor = (actor_t *)actor_malloc(sizeof(actor_t));

  if (!actor)
    return NULL;

  memset(actor, 0, sizeof(actor_t));

  list_init(&actor->actor_node);
  list_init(&actor->inbox);
  list_init(&actor->trash);

  mutex_create(&actor->mutex);
  cond_create(&actor->wait_cond);

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

  actor_pop(actor);

  mutex_lock(&actor->mutex);

  while (!list_isempty(&actor->trash)) {
    p = list_shift(&actor->trash);
    msg = list_entry(p, mailmsg_t, mail_node);
    actor_free(msg);
  }

  while (!list_isempty(&actor->inbox)) {
    p = list_shift(&actor->inbox);
    msg = list_entry(p, mailmsg_t, mail_node);
    actor_free(msg);
  }

  mutex_unlock(&actor->mutex);

  cond_destroy(&actor->wait_cond);
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

  func(arg);

  tls_setvalue(tls, NULL);
  actor_destroy(actor);
}

static void actor_thread(void *arg) {
  actorwrap_t *wrap = (actorwrap_t *)arg;
  actor_wrap(wrap->func, wrap->arg);
  actor_free(wrap);
}

actorid_t actor_spawn(void (*func)(void *), void *arg) {
  actorid_t actor_id = 0;
  actorwrap_t *wrap;
  thread_t thread;

  wrap = (actorwrap_t *)actor_malloc(sizeof(actorwrap_t));

  if (!wrap)
    return -1;

  wrap->func = func;
  wrap->arg = arg;

  actor_id = thread_start(&thread, actor_thread, wrap);
  thread_detach(&thread);

  return actor_id;
}

int actor_receive(actormsg_t *actor_msg, unsigned int timeout) {
  actor_t *actor = actor_current();
  list_t *node;
  mailmsg_t *msg;
  int retval = 1;

  if (!actor)
    return -1;

  mutex_lock(&actor->mutex);

  if (list_isempty(&actor->inbox)) {
    actor->waiting += 1;
    retval = cond_timedwait(&actor->wait_cond, &actor->mutex, timeout);
    actor->waiting -= 1;

    if (retval < 1) {
      mutex_unlock(&actor->mutex);
      return retval;
    }
  }

  node = list_shift(&actor->inbox);
  msg = list_entry(node, mailmsg_t, mail_node);

  if (actor_msg)
    *actor_msg = msg->actor_msg;

  list_push(&actor->trash, &msg->mail_node);

  mutex_unlock(&actor->mutex);

  return retval;
}

static int actor_sendto(actor_t *actor, int type, const void *data, int size) {
  actorid_t sender = actor_self();
  mailmsg_t *msg;

  if (sender < 0)
    return -1;

  msg = (mailmsg_t *)actor_malloc(sizeof(mailmsg_t) + size);

  if (!msg)
    return -1;

  list_init(&msg->mail_node);

  memcpy(msg->buffer, data, size);

  msg->actor_msg.receiver = actor->actor_id;
  msg->actor_msg.sender = sender;
  msg->actor_msg.type = type;
  msg->actor_msg.data = msg->buffer;
  msg->actor_msg.size = size;

  mutex_lock(&actor->mutex);

  list_push(&actor->inbox, &msg->mail_node);

  if (actor->waiting > 0)
    cond_signal(&actor->wait_cond);

  mutex_unlock(&actor->mutex);

  return 0;
}

int actor_send(actorid_t actor_id, int type, const void *data, int size) {
  actor_t *actor = actor_query(actor_id);

  if (!actor)
    return -1;

  if (!data)
    return -1;

  if (size <= 0)
    return -1;

  return actor_sendto(actor, type, data, size);
}

int actor_reply(actormsg_t *msg, int type, const void *data, int size) {
  return actor_send(msg->sender, type, data, size);
}

int actor_broadcast(int type, const void *data, int size) {
  actor_t *actor;
  list_t *p, *t;
  int counter = 0;

  mutex_lock(&actor_mutex);

  list_foreach(&actor_list, p, t) {
    actor = list_entry(p, actor_t, actor_node);

    if (0 == actor_sendto(actor, type, data, size))
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

  while (!list_isempty(&actor->trash)) {
    p = list_shift(&actor->trash);
    msg = list_entry(p, mailmsg_t, mail_node);
    actor_free(msg);
  }

  mutex_unlock(&actor->mutex);
}
