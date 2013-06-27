#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/system_properties.h>

#include "device_database/device_database.h"
#include "ptmx.h"

unsigned long int
get_ptmx_fops_address(void)
{
  unsigned long int address;

  address = device_get_symbol_address(DEVICE_SYMBOL(ptmx_fops));
  if (address) {
    return address;
  }

  if (kallsyms_exist()) {
    address = kallsyms_get_symbol_address("ptmx_fops");
    if (address) {
      return address;
    }
  }

  return 0;
}
