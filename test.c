/*
 *  test.c
 *
 *  copyright (c) 2019, 2020 Xiongfei Shi
 *
 *  author: Xiongfei Shi <xiongfei.shi(a)icloud.com>
 *  license: Apache-2.0
 *
 *  https://github.com/shixiongfei/actor
 */

#include <stdarg.h>
#include <stdio.h>
#include <sys/timeb.h>
#include <time.h>

#include "actor.h"

#ifndef _WIN32
#define dynarray(type, name, size) type name[size]
#else
#include <malloc.h>
#define dynarray(type, name, size)                                             \
  type *name = (type *)_alloca((size) * sizeof(type))
#endif

enum {
  LG_CURLEVEL = -1,
  LG_TRACE,
  LG_DEBUG,
  LG_INFO,
  LG_WARN,
  LG_ERROR,
  LG_FATAL,
  LG_DISABLE,
  LG_MAXLEVEL
};

typedef struct Console {
  actorid_t actor_id;
  int level;
  FILE *fp;
} Console;

typedef struct ConsoleCommand {
  FILE *fp;
  long sec, usec;
  int level;
  int size;
  char data[1];
} ConsoleCommand;

enum { EV_CSLQUIT, EV_CSLPRINT };

static Console console = {0};
static const char *level_names[] = {
    "TRACE", "DEBUG", "INFO ", "WARN ", "ERROR", "FATAL", "DISABLE",
};
static const char *level_colors[] = {
#ifdef _WIN32
    "", "", "", "", "", "",
#else
    "\x1b[94m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[35m",
#endif
};
#ifdef _WIN32
static const char default_color[] = "";
#else
static const char default_color[] = "\x1b[0m";
#endif

static void cslcmd_print(ConsoleCommand *cslcmd) {
  struct tm lt;
  char prefix[36] = {0};

#ifndef _WIN32
  localtime_r((time_t *)&cslcmd->sec, &lt);
#else
  do {
    time_t ts = cslcmd->sec;
    localtime_s(&lt, &ts);
  } while (0);
#endif

  snprintf(prefix, sizeof(prefix), "%04d-%02d-%02d %02d:%02d:%02d.%06ld %s | ",
           lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday, lt.tm_hour, lt.tm_min,
           lt.tm_sec, cslcmd->usec, level_names[cslcmd->level]);

  fprintf(cslcmd->fp, "%s%s%s%s\n", level_colors[cslcmd->level], prefix,
          (const char *)cslcmd->data, default_color);
  fflush(cslcmd->fp);
}

static void console_actor(void *args) {
  actorid_t actor_id = actor_self();
  actormsg_t actor_msg;
  int quit = 0;

  do {
    actor_tickupdate();

    if (actor_receive(&actor_msg, 0x7fffffff) != ACTOR_SUCCESS)
      continue;

    switch (actor_msg.type) {
    case EV_CSLQUIT:
      actor_shutdown(actor_id);
      quit = 1;
      break;
    case EV_CSLPRINT:
      cslcmd_print((ConsoleCommand *)actor_msg.data);
      break;
    }
  } while (!quit || actor_receivable(actor_id));
}

static int console_level(int level) {
  int curlevel = console.level;

  if (LG_TRACE <= level && level <= LG_DISABLE)
    console.level = level;

  return curlevel;
}

static FILE *console_output(FILE *fp) {
  FILE *curfp = console.fp;

  if (fp != NULL) {
    console.fp = fp;

    if (curfp)
      fflush(curfp);
  }

  return curfp;
}

static int console_print(int level, const char *format, ...) {
  ConsoleCommand *cslcmd;
  va_list args, ap;
  struct timeb tb;
  int nbytes, retval = 0;

  if (level < console.level)
    return 0;

  if (!actor_sendable(console.actor_id))
    return 0;

  va_start(args, format);
  va_copy(ap, args);

  nbytes = vsnprintf(NULL, 0, format, ap);

  if (nbytes > 0) {
    dynarray(unsigned char, buffer, sizeof(ConsoleCommand) + nbytes);
    cslcmd = (ConsoleCommand *)buffer;

    cslcmd->fp = console.fp;
    cslcmd->level = level;
    cslcmd->size = nbytes;

    ftime(&tb);
    cslcmd->sec = (long)tb.time;
    cslcmd->usec = (long)tb.millitm * 1000;

    vsnprintf(cslcmd->data, cslcmd->size + 1, format, args);
    retval = actor_send(console.actor_id, ACTOR_HIGH, EV_CSLPRINT, cslcmd,
                        sizeof(ConsoleCommand) + nbytes);
  }

  va_end(args);

  return (0 == retval) ? nbytes : 0;
}

#define LG_Trace(format, ...) console_print(LG_TRACE, format, ##__VA_ARGS__)
#define LG_Debug(format, ...) console_print(LG_DEBUG, format, ##__VA_ARGS__)
#define LG_Info(format, ...) console_print(LG_INFO, format, ##__VA_ARGS__)
#define LG_Warn(format, ...) console_print(LG_WARN, format, ##__VA_ARGS__)
#define LG_Error(format, ...) console_print(LG_ERROR, format, ##__VA_ARGS__)
#define LG_Fatal(format, ...) console_print(LG_FATAL, format, ##__VA_ARGS__)

static int console_start(int level, FILE *fp) {
  console_level(level);
  console_output(fp);
  console.actor_id = actor_spawn(console_actor, NULL);

  LG_Trace("console module is started.");
  return 0;
}

static void console_stop(void) {
  LG_Trace("console module is stopped.");

  actor_send(console.actor_id, ACTOR_LOW, EV_CSLQUIT, NULL, 0);
  actor_wait(console.actor_id, 0x7fffffff);
}

/* -------------------------------------------------------------------------  */

static actorid_t ping, pong;

static void actor_ping(void *arg) {
  actormsg_t cmd = {0}, msg = {0};
  int timers = 5;

  LG_Info("Actor Ping ID: %ld", actor_self());

  actor_receive(&cmd, 0x7fffffff);

  while (timers--) {
    actor_tickupdate();

    actor_send(pong, ACTOR_HIGH, 0, "PING", 5);
    actor_receive(&msg, 5000);

    LG_Info("Actor Ping Receive(%d:%d) %s From %ld", msg.type, msg.size,
            (const char *)msg.data, msg.sender);
  }

  actor_reply(&cmd, cmd.priority, cmd.type, "FINISHED", 9);
}

static void actor_pong(void *arg) {
  actormsg_t msg = {0};

  LG_Info("Actor Pong ID: %ld", actor_self());

  while (1) {
    actor_tickupdate();

    actor_receive(&msg, 0x7fffffff);

    LG_Info("Actor Pong Receive(%d:%d) %s From %ld", msg.type, msg.size,
            (const char *)msg.data, msg.sender);

    actor_reply(&msg, msg.priority, 1, "PONG", 5);
  }
}

typedef struct Args {
  int retval;
  int argc;
  char **argv;
} Args;

static void actor_main(void *arg) {
  Args *args = (Args *)arg;
  actormsg_t msg = {0};

  console_start(LG_TRACE, stderr);

  LG_Info("CPU Nums: %d", actor_cpunum());
  LG_Info("Actor Main ID: %ld", actor_self());

  ping = actor_spawn(actor_ping, NULL);
  pong = actor_spawn(actor_pong, NULL);
  LG_Info("Spawned Ping: %ld, Pong: %ld", ping, pong);

  actor_send(ping, ACTOR_LOW, -1, "START", 6);
  actor_receive(&msg, 0x7fffffff);

  actor_tickupdate();

  console_stop();

  args->retval = 0;
}

int main(int argc, char *argv[]) {
  Args args = {-1, argc, argv};

  actor_initialize();
  actor_wrap(actor_main, &args);
  actor_finalize();

  return args.retval;
}
