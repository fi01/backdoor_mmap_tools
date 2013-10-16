#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/system_properties.h>
#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "device_database/device_database.h"
#include "libkallsyms/kallsyms_in_memory.h"
#include "backdoor_mmap.h"

#define MAX_CCS_SEARCH_BINARY_HANDLERS  2

typedef struct _supported_device {
  device_id_t device_id;
  unsigned long int ccsecurity_ops_address;
  unsigned long int search_binary_handler_address;
  unsigned long int __ccs_search_binary_handler_address[MAX_CCS_SEARCH_BINARY_HANDLERS];
} supported_device;

static supported_device supported_devices[] = {
  { DEVICE_L01E_V20b, 0xc0daeab0, 0xc0132310, { 0xc0208564, 0xc020aec0, }, },
  { DEVICE_L02E_V20a, 0xc0c145a0, 0xc0149c4c, { 0xc020e604, 0xc02110d4, }, },
  { DEVICE_P02E_10_0657, 0xc0dc8d60, 0xc013031c, { 0xc0267550, 0xc0269eac, }, },
  { DEVICE_P02E_10_0798, 0xc0dc8d60, 0xc013041c, { 0xc0267650, 0xc0269fac, }, },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

static void *ccsecurity_ops;
static void *search_binary_handler;
static void **__ccs_search_binary_handler;

static kallsyms *kallsyms_info;

static bool
kallsyms_init(void)
{
  if (!kallsyms_info) {
    kallsyms_info = kallsyms_in_memory_init((void *)BACKDOOR_MMAP_ADDRESS, BACKDOOR_MMAP_SIZE);
    if (!kallsyms_info) {
      return false;
    }
  }

  return true;
}

static void *
lookup_symbol_name(const char *name)
{
  if (!kallsyms_init()) {
    return NULL;
  }

  return (void *)kallsyms_in_memory_lookup_name(kallsyms_info, name);
}

static const char *
lookup_symbol_address(void *address)
{
  if (!kallsyms_init()) {
    return NULL;
  }

  return kallsyms_in_memory_lookup_address(kallsyms_info, (unsigned long)address);
}

static bool
setup_variables(void)
{
  device_id_t device_id = detect_device();
  int i;

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id == device_id) {
      ccsecurity_ops = (void *)supported_devices[i].ccsecurity_ops_address;
      search_binary_handler = (void *)supported_devices[i].search_binary_handler_address;
      __ccs_search_binary_handler = (void **)supported_devices[i].__ccs_search_binary_handler_address;
      break;
    }
  }

  if (!ccsecurity_ops) {
    ccsecurity_ops = lookup_symbol_name("ccsecurity_ops");
  }

  if (!search_binary_handler) {
    search_binary_handler = lookup_symbol_name("search_binary_handler");
  }

  return ccsecurity_ops && search_binary_handler;
}

#define NUM_CCSECURITY_OPS  39
#define BINARY_HANDLER_POS  35

static bool
disable_ccsecurity(void)
{
  void **p;
  int i;

  p = backdoor_convert_to_mmaped_address(ccsecurity_ops);

  if (p[BINARY_HANDLER_POS] == search_binary_handler) {
    printf("Already disabled??\nUnlock anyway.\n");
  }
  else if (__ccs_search_binary_handler) {
    for (i = 0; i < MAX_CCS_SEARCH_BINARY_HANDLERS; i++) {
      if (__ccs_search_binary_handler[i] && p[BINARY_HANDLER_POS] == __ccs_search_binary_handler[i]) {
	break;
      }
    }

    if (i == MAX_CCS_SEARCH_BINARY_HANDLERS) {
      printf("check failed: ccsecurity_ops[%d] = %%p\n", BINARY_HANDLER_POS, p[BINARY_HANDLER_POS]);
      return false;
    }
  }
  else {
    const char *name = lookup_symbol_address(p[BINARY_HANDLER_POS]);

    if (strcmp(name, "__ccs_search_binary_handler")) {
      printf("check failed: ccsecurity_ops[%d] = %s\n", BINARY_HANDLER_POS, name);
      return false;
    }
  }

  for (i = 0; i < NUM_CCSECURITY_OPS; i++) {
    switch (i) {
    case BINARY_HANDLER_POS:
      p[i] = search_binary_handler;
      break;
    default:
      p[i] = 0;
    }
  }

  return true;
}

int
main(int argc, char **argv)
{
  if (!backdoor_open_mmap()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));
    printf("Run 'install_backdoor' first\n");

    exit(EXIT_FAILURE);
  }

  if (!setup_variables()) {
    print_reason_device_not_supported();

    backdoor_close_mmap();
    exit(EXIT_FAILURE);
  }

  if (!disable_ccsecurity()) {
    printf("Disable ccsecurity failed\n");

    backdoor_close_mmap();
    exit(EXIT_FAILURE);
  }

  backdoor_close_mmap();

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
