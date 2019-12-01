/*
 *  actor.h
 *
 *  copyright (c) 2019 Xiongfei Shi
 *
 *  author: Xiongfei Shi <jenson.shixf(a)gmail.com>
 *  license: Apache-2.0
 *
 *  https://github.com/shixiongfei/actor
 */

#ifndef __ACTOR_H__
#define __ACTOR_H__

#include <stddef.h>

#ifndef _WIN32
#define ACTOR_EXPORT __attribute__((visibility("default")))
#define ACTOR_IMPORT __attribute__((visibility("default")))
#else
#define ACTOR_EXPORT __declspec(dllexport)
#define ACTOR_IMPORT __declspec(dllimport)
#endif

#if defined(ACTOR_STATIC)
#define ACTOR_API extern
#elif defined(ACTOR_BUILD_DLL)
#define ACTOR_API ACTOR_EXPORT
#else
#define ACTOR_API ACTOR_IMPORT
#endif

#define ACTOR_QUOTEX(x) #x
#define ACTOR_QUOTE(x) ACTOR_QUOTEX(x)

#define ACTOR_MAJOR 0
#define ACTOR_MINOR 1
#define ACTOR_PATCH 0

#define ACTOR_VERMAJOR ACTOR_QUOTE(ACTOR_MAJOR)
#define ACTOR_VERMINOR ACTOR_QUOTE(ACTOR_MINOR)
#define ACTOR_VERPATCH ACTOR_QUOTE(ACTOR_PATCH)

#define ACTOR_VERNUM ((ACTOR_MAJOR * 100) + ACTOR_MINOR)
#define ACTOR_VERFULL ((ACTOR_VERNUM * 100) + ACTOR_PATCH)
#define ACTOR_VERSION (ACTOR_VERMAJOR "." ACTOR_VERMINOR "." ACTOR_VERPATCH)

#ifdef __cplusplus
extern "C" {
#endif

typedef long actorid_t;

typedef struct actormsg_s {
  actorid_t sender;
  actorid_t receiver;
  int type;
  int size;
  void *data;
} actormsg_t;

ACTOR_API void actor_setalloc(void *(*alloc)(size_t), void (*release)(void *));

ACTOR_API int actor_cpunum(void);

ACTOR_API void actor_initialize(void);
ACTOR_API void actor_finalize(void);

ACTOR_API void actor_wrap(void (*func)(void *), void *arg);
ACTOR_API actorid_t actor_spawn(void (*func)(void *), void *arg);
ACTOR_API int actor_receive(actormsg_t *actor_msg, unsigned int timeout);
ACTOR_API int actor_send(actorid_t actor_id, int type, const void *data,
                         int size);
ACTOR_API int actor_reply(actormsg_t *msg, int type, const void *data,
                          int size);
ACTOR_API int actor_broadcast(int type, const void *data, int size);
ACTOR_API actorid_t actor_self(void);

#ifdef __cplusplus
};
#endif

#endif /* __ACTOR_H__ */
