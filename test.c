/*
 *  test.c
 *
 *  copyright (c) 2019 Xiongfei Shi
 *
 *  author: Xiongfei Shi <jenson.shixf(a)gmail.com>
 *  license: Apache-2.0
 *
 *  https://github.com/shixiongfei/actor
 */

#include <stdio.h>

#include "actor.h"

static actorid_t ping, pong;

static void actor_ping(void *arg) {
  actormsg_t cmd = {0}, msg = {0};
  int timers = 5;

  printf("Actor Ping ID: %ld\n", actor_self());

  actor_receive(&cmd, 0x7fffffff);

  while (timers--) {
    actor_send(pong, 0, "PING", 5);
    actor_receive(&msg, 5000);

    printf("Actor Ping Receive(%d:%d) %s From %ld\n", msg.type, msg.size,
           (const char *)msg.data, msg.sender);
  }

  actor_reply(&cmd, cmd.type, "FINISHED", 8);
}

static void actor_pong(void *arg) {
  actormsg_t msg = {0};

  printf("Actor Pong ID: %ld\n", actor_self());

  while (1) {
    actor_receive(&msg, 0x7fffffff);

    printf("Actor Pong Receive(%d:%d) %s From %ld\n", msg.type, msg.size,
           (const char *)msg.data, msg.sender);

    actor_reply(&msg, 1, "PONG", 5);
  }
}

static void actor_main(void *arg) {
  actormsg_t msg = {0};

  printf("Actor Main ID: %ld\n", actor_self());

  actor_send(ping, -1, "START", 5);
  actor_receive(&msg, 0x7fffffff);
}

int main(int argc, char *argv[]) {
  actor_initialize();

  ping = actor_spawn(actor_ping, NULL);
  pong = actor_spawn(actor_pong, NULL);

  printf("Spawned Ping: %ld, Pong: %ld\n", ping, pong);

  actor_wrap(actor_main, NULL);

  actor_finalize();

  return 0;
}
