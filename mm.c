#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>

#include "device_database/device_database.h"
#include "kallsyms.h"
#include "mm.h"

typedef struct _supported_device {
  device_id_t device_id;
  unsigned long int remap_pfn_range_address;
} supported_device;

static supported_device supported_devices[] = {
  { DEVICE_HTL21_1_29_970_1,       0xc00ff32c },
  { DEVICE_HTL22_1_05_970_1,       0xc0128b10 },
  { DEVICE_HTX21_1_20_971_1,       0xc00fa8b0 },
  { DEVICE_IS17SH_01_00_04,        0xc0208a34 },
  { DEVICE_LT26W_1266_3278_6_2_B_0_200, 0xc0136294 },
  { DEVICE_LT29I_1266_3325_9_1_B_0_411, 0xc010ac30 },
  { DEVICE_SC04E_OMUAMDI,          0xc011383c },
  { DEVICE_SH04E_01_00_02,         0xc00e458c },
  { DEVICE_SH04E_01_00_03,         0xc00e46bc },
  { DEVICE_SOL21_9_1_D_0_395,      0xc010e33c },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

unsigned long int
_get_remap_pfn_range_address(void)
{
  device_id_t device_id = detect_device();
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
