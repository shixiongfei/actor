/*
 *  threads.h
 *
 *  copyright (c) 2019, 2020 Xiongfei Shi
 *
 *  author: Xiongfei Shi <xiongfei.shi(a)icloud.com>
 *  license: Apache-2.0
 *
 *  https://github.com/shixiongfei/actor
 */

#ifndef __THREADS_H__
#define __THREADS_H__

#ifndef _WIN32
#include <pthread.h>
#else
#include <Windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

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

typedef struct sema_s {
  mutex_t mutex;
  cond_t cond;
  unsigned int value;
} sema_t;

typedef struct rwlock_s {
  int write;
  int read;
} rwlock_t;

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

int sema_init(sema_t *sem, unsigned int value);
void sema_destroy(sema_t *sem);
void sema_post(sema_t *sem);
void sema_wait(sema_t *sem);
int sema_trywait(sema_t *sem);

void rwlock_init(rwlock_t *lock);
void rwlock_rlock(rwlock_t *lock);
void rwlock_wlock(rwlock_t *lock);
void rwlock_runlock(rwlock_t *lock);
void rwlock_wunlock(rwlock_t *lock);

int tls_create(tls_t *tls);
void tls_destroy(tls_t tls);
int tls_setvalue(tls_t tls, void *val);
void *tls_getvalue(tls_t tls);

int thread_start(thread_t *thread, void (*func)(void *), void *arg);
int thread_join(thread_t *thread);
int thread_detach(thread_t *thread);
int thread_kill(thread_t *thread);
void thread_sleep(unsigned int millisec);

#ifdef __cplusplus
};
#endif

#endif /* __THREADS_H__ */
