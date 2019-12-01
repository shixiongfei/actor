/*
 *  internal.h
 *
 *  copyright (c) 2019 Xiongfei Shi
 *
 *  author: Xiongfei Shi <jenson.shixf(a)gmail.com>
 *  license: Apache-2.0
 *
 *  https://github.com/shixiongfei/actor
 */

#ifndef __INTERNAL_H__
#define __INTERNAL_H__

#ifndef _WIN32
#include <pthread.h>
#else
#include <Windows.h>
#endif

#include "actor.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct allocator_s {
  void *(*alloc)(size_t);
  void (*release)(void *);
} allocator_t;

extern allocator_t allocator;

#define actor_malloc(size) allocator.alloc(size)
#define actor_free(ptr) allocator.release(ptr)

#ifdef _MSC_VER
#define THREAD_LOCAL __declspec(thread)

#define atom_incr(p) InterlockedIncrement((LONG volatile *)(p))
#define atom_decr(p) InterlockedDecrement((LONG volatile *)(p))
#define atom_cas(p, o, n) ((o) == InterlockedCompareExchange((p), (n), (o)))
#define atom_set(p, v) InterlockedExchange((LONG volatile *)(p), (v))
#define atom_sync() MemoryBarrier()
#define atom_spinlock(p)                                                       \
  while (InterlockedExchange((LONG volatile *)(p), 1)) {                       \
  }
#define atom_spinunlock(p) InterlockedExchange((LONG volatile *)(p), 0)
#else /* _MSC_VER */
#define THREAD_LOCAL __thread

#define atom_incr(p) __sync_add_and_fetch((p), 1)
#define atom_decr(p) __sync_sub_and_fetch((p), 1)
#define atom_cas(p, o, n) __sync_bool_compare_and_swap((p), (o), (n))
#define atom_set(p, v) __sync_lock_test_and_set((p), (v))
#define atom_sync() __sync_synchronize()
#define atom_spinlock(p)                                                       \
  while (__sync_lock_test_and_set((p), 1)) {                                   \
  }
#define atom_spinunlock(p) __sync_lock_release(p)
#endif /* _MSC_VER */

#define atom_get(p, v)                                                         \
  do {                                                                         \
    *(v) = *(p);                                                               \
  } while (!atom_cas((p), *(v), *(v)))

#ifndef _WIN32
typedef pthread_mutex_t mutex_t;
typedef pthread_cond_t cond_t;
typedef pthread_key_t tls_t;
#else
typedef HANDLE pthread_t;
typedef CRITICAL_SECTION mutex_t;
typedef CONDITION_VARIABLE cond_t;
typedef DWORD tls_t;
#endif

typedef pthread_t thread_t;

int mutex_create(mutex_t *mtx);
void mutex_destroy(mutex_t *mtx);
void mutex_lock(mutex_t *mtx);
int mutex_trylock(mutex_t *mtx);
void mutex_unlock(mutex_t *mtx);

int cond_create(cond_t *cnd);
void cond_destroy(cond_t *cnd);
int cond_wait(cond_t *cnd, mutex_t *mtx);
/* Return: -1 Failed. 0 Timedout. 1 Success. */
int cond_timedwait(cond_t *cnd, mutex_t *mtx, unsigned int millisec);
int cond_signal(cond_t *cnd);
int cond_broadcast(cond_t *cnd);

int tls_create(tls_t *tls);
void tls_destroy(tls_t tls);
int tls_setvalue(tls_t tls, void *val);
void *tls_getvalue(tls_t tls);

int thread_gettid(void);

int thread_start(thread_t *thread, void (*func)(void *), void *arg);
int thread_join(thread_t *thread);
int thread_detach(thread_t *thread);
int thread_kill(thread_t *thread);

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

#endif /* __INTERNAL_H__ */
