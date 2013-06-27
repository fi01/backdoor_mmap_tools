#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>

#include "device_database/device_database.h"
#include "kallsyms.h"
#include "mm.h"

unsigned long int
_get_remap_pfn_range_address(void)
{
  unsigned long int address = device_get_symbol_address(DEVICE_SYMBOL(remap_pfn_range));

  if (address) {
    return address;
  }

  return 0;
}

void *
get_remap_pfn_range_address(void)
{
  void *ret = NULL;

  if (kallsyms_exist()) {
    ret = kallsyms_get_symbol_address("remap_pfn_range");
  }

  if (!ret) {
    ret = (void*)_get_remap_pfn_range_address();
  }

  if (!ret) {
    print_reason_device_not_supported();
    return NULL;
  }

  return ret;
}
