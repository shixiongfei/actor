/*
 *  threads.c
 *
 *  copyright (c) 2019, 2020 Xiongfei Shi
 *
 *  author: Xiongfei Shi <jenson.shixf(a)gmail.com>
 *  license: Apache2.0
 *
 *  https://github.com/shixiongfei/actor
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif
#else /* _WIN32 */
#include <Windows.h>
#include <process.h>
#endif /* _WIN32 */

#include "actor.h"
#include "threads.h"

extern void *actor_malloc(size_t);
extern void actor_free(void *);

#ifndef _WIN32
int mutex_create(mutex_t *mtx) {
  int retval = -1;

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  retval = pthread_mutex_init(mtx, &attr);
  pthread_mutexattr_destroy(&attr);

  return (0 == retval) ? 0 : -1;
}

void mutex_destroy(mutex_t *mtx) { pthread_mutex_destroy(mtx); }

void mutex_lock(mutex_t *mtx) { pthread_mutex_lock(mtx); }

int mutex_trylock(mutex_t *mtx) {
  return (0 == pthread_mutex_trylock(mtx)) ? 0 : -1;
}

void mutex_unlock(mutex_t *mtx) { pthread_mutex_unlock(mtx); }
#else
int mutex_create(mutex_t *mtx) {
  InitializeCriticalSection(mtx);
  return 0;
}

void mutex_destroy(mutex_t *mtx) { DeleteCriticalSection(mtx); }

void mutex_lock(mutex_t *mtx) { EnterCriticalSection(mtx); }

int mutex_trylock(mutex_t *mtx) {
  return (TRUE == TryEnterCriticalSection(mtx)) ? 0 : -1;
}

void mutex_unlock(mutex_t *mtx) { LeaveCriticalSection(mtx); }
#endif

#ifndef _WIN32
int cond_create(cond_t *cnd) {
  return (0 == pthread_cond_init(cnd, NULL)) ? 0 : -1;
}

void cond_destroy(cond_t *cnd) { pthread_cond_destroy(cnd); }

int cond_wait(cond_t *cnd, mutex_t *mtx) {
  return (0 == pthread_cond_wait(cnd, mtx)) ? 0 : -1;
}

int cond_timedwait(cond_t *cnd, mutex_t *mtx, unsigned int millisec) {
  int retval = EINTR;

  struct timeval now;
  struct timespec ts;

  gettimeofday(&now, NULL);

  now.tv_sec += millisec * 0.001;
  now.tv_usec += (millisec % 1000) * 1000;

  if (now.tv_usec >= 1000000) {
    now.tv_usec -= 1000000;
    now.tv_sec += 1;
  }

  ts.tv_sec = now.tv_sec;
  ts.tv_nsec = now.tv_usec * 1000;

  while (EINTR == retval)
    retval = pthread_cond_timedwait(cnd, mtx, &ts);

  return (0 == retval) ? 1 : (ETIMEDOUT == retval) ? 0 : -1;
}

int cond_signal(cond_t *cnd) {
  return (0 == pthread_cond_signal(cnd)) ? 0 : -1;
}

int cond_broadcast(cond_t *cnd) {
  return (0 == pthread_cond_broadcast(cnd)) ? 0 : -1;
}
#else
int cond_create(cond_t *cnd) {
  InitializeConditionVariable(cnd);
  return 0;
}

void cond_destroy(cond_t *cnd) { ((void *)cnd); }

int cond_wait(cond_t *cnd, mutex_t *mtx) {
  return 1 == cond_timedwait(cnd, mtx, INFINITE);
}

int cond_timedwait(cond_t *cnd, mutex_t *mtx, unsigned int millisec) {
  return (TRUE == SleepConditionVariableCS(cnd, mtx, millisec))
             ? 1
             : (ERROR_TIMEOUT == GetLastError()) ? 0 : -1;
}

int cond_signal(cond_t *cnd) {
  WakeConditionVariable(cnd);
  return 0;
}

int cond_broadcast(cond_t *cnd) {
  WakeAllConditionVariable(cnd);
  return 0;
}
#endif

int sema_init(sema_t *sem, unsigned int value) {
  if (0 != mutex_create(&sem->mutex))
    return -1;

  if (0 != cond_create(&sem->cond)) {
    mutex_destroy(&sem->mutex);
    return -1;
  }

  sem->value = value;
  return 0;
}

void sema_destroy(sema_t *sem) {
  cond_destroy(&sem->cond);
  mutex_destroy(&sem->mutex);
}

void sema_post(sema_t *sem) {
  mutex_lock(&sem->mutex);
  sem->value += 1;
  if (sem->value > 0)
    cond_signal(&sem->cond);
  mutex_unlock(&sem->mutex);
}

void sema_wait(sema_t *sem) {
  mutex_lock(&sem->mutex);
  while (0 == sem->value)
    cond_wait(&sem->cond, &sem->mutex);
  sem->value -= 1;
  mutex_unlock(&sem->mutex);
}

int sema_trywait(sema_t *sem) {
  if (0 != mutex_trylock(&sem->mutex))
    return -1;

  if (0 == sem->value) {
    mutex_unlock(&sem->mutex);
    return -1;
  }

  sem->value -= 1;
  mutex_unlock(&sem->mutex);
  return 0;
}

#ifndef _WIN32
int tls_create(tls_t *tls) {
  return (0 == pthread_key_create(tls, NULL)) ? 0 : -1;
}

void tls_destroy(tls_t tls) { pthread_key_delete(tls); }

int tls_setvalue(tls_t tls, void *val) {
  return (0 == pthread_setspecific(tls, val)) ? 0 : -1;
}

void *tls_getvalue(tls_t tls) { return pthread_getspecific(tls); }
#else
/*
   https://msdn.microsoft.com/en-us/library/ms686749(v=vs.85).aspx
   The constant TLS_MINIMUM_AVAILABLE defines the minimum number of TLS indexes
   available in each process. This minimum is guaranteed to be at least 64 for
   all systems. The maximum number of indexes per process is 1,088.
 */

int tls_create(tls_t *tls) {
  *tls = TlsAlloc();
  return (TLS_OUT_OF_INDEXES == (*tls)) ? -1 : 0;
}

void tls_destroy(tls_t tls) { TlsFree(tls); }

int tls_setvalue(tls_t tls, void *val) {
  return (TRUE == TlsSetValue(tls, val)) ? 0 : -1;
}

void *tls_getvalue(tls_t tls) { return TlsGetValue(tls); }
#endif

#ifndef _WIN32
#if defined(__linux__)
#define gettid() syscall(__NR_gettid)
#elif defined(__APPLE__) || defined(__BSD__)
#define gettid() pthread_mach_thread_np(pthread_self())
#endif

#define DECLARE_THREAD_CB(nm, arg) static void *nm(void *arg)
#define THREAD_CODE(x) ((void *)((intptr_t)(x)))

static void thread_killer(int sig) { pthread_exit(NULL); }
#else
#define pthread_exit(n) _endthreadex(n)
#define pthread_create(h, a, f, p)                                             \
  ((HANDLE)-1 == ((*h) = (HANDLE)_beginthreadex(NULL, (a), (f), (p), 0, NULL)) \
       ? -1                                                                    \
       : 0)

static int pthread_join(pthread_t h, void **retval) {
  DWORD dwExitCode = 0;

  if (GetExitCodeThread(h, &dwExitCode) && (STILL_ACTIVE == dwExitCode))
    WaitForSingleObject(h, INFINITE);

  CloseHandle(h);

  if (retval)
    *retval = (void *)(intptr_t)dwExitCode;

  return 0;
}

static int pthread_detach(pthread_t h) { return CloseHandle(h) ? 0 : -1; }

#define SIGUSR1 0

static int pthread_kill(pthread_t h, int sig) {
  return TerminateThread(h, 0) ? 0 : -1;
}

#define gettid() GetCurrentThreadId()
#define DECLARE_THREAD_CB(nm, arg) static unsigned int __stdcall nm(void *arg)
#define THREAD_CODE(x) ((unsigned int)(x))
#endif /* _WIN32 */

#ifndef _WIN32
int actor_cpunum(void) { return (int)sysconf(_SC_NPROCESSORS_ONLN); }
#else
int actor_cpunum(void) {
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  return (int)si.dwNumberOfProcessors;
}
#endif

#ifndef _WIN32
int actor_getpid(void) { return (int)getpid(); }
#else
int actor_getpid(void) { return _getpid(); }
#endif

int actor_gettid(void) { return gettid(); }

typedef struct threadctx_s {
  void (*func)(void *);
  void *arg;
} threadctx_t;

DECLARE_THREAD_CB(cthread_entry, param) {
  threadctx_t *ctx = (threadctx_t *)param;

#ifndef _WIN32
  struct sigaction act;

  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  act.sa_handler = thread_killer;

  sigaction(SIGUSR1, &act, NULL);
#endif

  ctx->func(ctx->arg);
  actor_free(ctx);

  return THREAD_CODE(0);
}

int thread_start(thread_t *thread, void (*func)(void *), void *arg) {
  threadctx_t *ctx = (threadctx_t *)actor_malloc(sizeof(threadctx_t));

  if (!ctx)
    return -1;

  ctx->func = func;
  ctx->arg = arg;

  if (0 != pthread_create(thread, 0, cthread_entry, ctx)) {
    actor_free(ctx);
    return -1;
  }
  return 0;
}

int thread_join(thread_t *thread) {
  return (0 == pthread_join(*thread, NULL)) ? 0 : -1;
}

int thread_detach(thread_t *thread) {
  return (0 == pthread_detach(*thread)) ? 0 : -1;
}

int thread_kill(thread_t *thread) {
  return (0 == pthread_kill(*thread, SIGUSR1)) ? 0 : -1;
}

void thread_sleep(unsigned int millisec) {
#ifndef _WIN32
  int was_error;
  struct timespec elapsed, tv;

  elapsed.tv_sec = (time_t)(millisec / 1000);
  elapsed.tv_nsec = (long)(millisec % 1000) * 1000000;

  do {
    errno = 0;

    tv.tv_sec = elapsed.tv_sec;
    tv.tv_nsec = elapsed.tv_nsec;

    was_error = nanosleep(&tv, &elapsed);
  } while (was_error && (EINTR == errno));
#else
  Sleep(millisec);
#endif
}
