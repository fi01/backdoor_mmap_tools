#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>

#include "detect_device.h"
#include "kallsyms.h"
#include "mm.h"

typedef struct _supported_device {
  int device_id;
  unsigned long int remap_pfn_range_address;
} supported_device;

static supported_device supported_devices[] = {
  { DEV_IS17SH_01_00_04,   0xc0208a34 },
  { DEV_SH04E_01_00_02,    0xc00e458c },
  { DEV_SOL21_9_1_D_0_395, 0xc010e33c },
  { DEV_HTL21_JRO03C,      0xc00ff32c },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

unsigned long int
_get_remap_pfn_range_address(void)
{
  int device_id = detect_device();
  unsigned long int ret;
  int i;

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id == device_id){
      return supported_devices[i].remap_pfn_range_address;
    }
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
