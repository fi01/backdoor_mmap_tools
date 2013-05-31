#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/system_properties.h>

#include "detect_device.h"
#include "ptmx.h"

typedef struct _supported_device {
  int device_id;
  unsigned long int ptmx_fops_address;
} supported_device;

static supported_device supported_devices[] = {
  { DEV_F11D_V24R40A   ,    0xc1056998 },
  { DEV_ISW12K_010_0_3000,  0xc0dc0a10 },
  { DEV_SCL21_KDALJD,       0xc0c71dc0 },

  // ptmx_fops is 0xc09fc5fc but it doesn't work (kernel 2.6.39.4)
  { DEV_ISW13F_V69R51I,     0xc09fc5fc + 4 },
  { DEV_F10D_V21R48A,       0xc09a60dc + 4 },

  { DEV_IS17SH_01_00_04,    0xc0edae90 },
  { DEV_SONYTABS_RELEASE5A, 0xc06e4d18 },
  { DEV_SONYTABP_RELEASE5A, 0xc06e6da0 },
  { DEV_SH04E_01_00_02,     0xc0eed190 },
  { DEV_SOL21_9_1_D_0_395,  0xc0d030c8 },
  { DEV_HTL21_JRO03C,       0xc0d1d944 },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

unsigned long int
get_ptmx_fops_address(void)
{
  int device_id = detect_device();
  int ret;
  int i;

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id == device_id) {
      return supported_devices[i].ptmx_fops_address;
    }
  }

  ret = kallsyms_get_symbol_address("ptmx_fops");
  if (!ret) {
    print_reason_device_not_supported();
    return 0;
  }

  return ret;
}
