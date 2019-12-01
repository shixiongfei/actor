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

int main(int argc, char *argv[]) {
  printf("ActorID: %ld\n", actor_self());

  return 0;
}
