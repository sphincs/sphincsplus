#include "cycles.h"

#if defined(__aarch64__) && defined(__APPLE__)
// Adapted from
// https://github.com/lemire/Code-used-on-Daniel-Lemire-s-blog/blob/master/2021/03/24/

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define KPERF_LIST                                                             \
  F(int, kpc_force_all_ctrs_set, int)                                          \
  F(int, kpc_set_counting, uint32_t)                                           \
  F(int, kpc_set_thread_counting, uint32_t)                                    \
  F(int, kpc_set_config, uint32_t, void *)                                     \
  F(uint32_t, kpc_get_counter_count, uint32_t)                                 \
  F(uint32_t, kpc_get_config_count, uint32_t)                                  \
  F(int, kpc_get_thread_counters, int, unsigned int, void *)

#define F(ret, name, ...)                                                      \
  typedef ret name##proc(__VA_ARGS__);                                         \
  static name##proc *name;
KPERF_LIST
#undef F

uint64_t g_counters[10];
uint64_t g_config[10];

static void configure_rdtsc(void) {
  if (kpc_set_config(3, g_config)) {
    printf("kpc_set_config failed\n");
    return;
  }

  if (kpc_force_all_ctrs_set(1)) {
    printf("kpc_force_all_ctrs_set failed\n");
    return;
  }

  if (kpc_set_counting(3)) {
    printf("kpc_set_counting failed\n");
    return;
  }

  if (kpc_set_thread_counting(3)) {
    printf("kpc_set_thread_counting failed\n");
    return;
  }
}

void init_cpucycles(void) {
  void *kperf = dlopen(
      "/System/Library/PrivateFrameworks/kperf.framework/Versions/A/kperf",
      RTLD_LAZY);
  if (!kperf) {
    printf("kperf = %p\n", kperf);
    return;
  }
#define F(ret, name, ...)                                                      \
  name = (name##proc *)(dlsym(kperf, #name));                                  \
  if (!name) {                                                                 \
    printf("%s = %p\n", #name, (void *)name);                                  \
    return;                                                                    \
  }
  KPERF_LIST
#undef F

  if (kpc_get_counter_count(3) != 10) {
    printf("wrong fixed counters count\n");
    return;
  }

  if (kpc_get_config_count(3) != 8) {
    printf("wrong fixed config count\n");
    return;
  }
  g_config[0] = 0x02 | 0x20000;
  g_config[3] = 0x8d | 0x20000;
  g_config[4] = 0xcb | 0x20000;
  g_config[5] = 0x8c | 0x20000;

  configure_rdtsc();
}

unsigned long long cpucycles(void) {
  static int warned = 0;
  if (kpc_get_thread_counters(0, 10, g_counters)) {
    if (!warned) {
      printf("kpc_get_thread_counters failed, run as sudo?\n");
      warned = 1;
    }
    return 1;
  }
  // g_counters[3 + 2] gives you the number of instructions 'decoded'
  // whereas g_counters[1] might give you the number of instructions 'retired'.
  return g_counters[0 + 2];
}
#else
void init_cpucycles(void) {
}

unsigned long long cpucycles(void)
{
  unsigned long long result;
  __asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
    : "=a" (result) ::  "%rdx");
  return result;
}
#endif
