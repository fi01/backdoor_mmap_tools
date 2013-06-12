#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/system_properties.h>

#include "device_database/device_database.h"
#include "ptmx.h"

typedef struct _supported_device {
  device_id_t device_id;
  unsigned long int ptmx_fops_address;
} supported_device;

static supported_device supported_devices[] = {
  // F10D: Fujitsu added a method in struct file_operations
  { DEVICE_F10D_V21R48A,            0xc09a60dc + 4 },
  { DEVICE_F11D_V24R40A,            0xc1056998 },
  { DEVICE_HTL21_1_29_970_1,        0xc0d1d944 },
  { DEVICE_HTL22_1_05_970_1,        0xc0df467c },
  { DEVICE_HTX21_1_20_971_1,        0xc0ccc0b4 },
  { DEVICE_ISW12K_010_0_3000,       0xc0dc0a10 },
  { DEVICE_IS17SH_01_00_04,         0xc0edae90 },
  // ISW13F: Fujitsu added a method in struct file_operations
  { DEVICE_ISW13F_V69R51I,          0xc09fc5fc + 4 },
  { DEVICE_LT26W_1266_3278_6_2_B_0_200, 0xc0cc3dc0 },
  { DEVICE_LT29I_1266_3325_9_1_B_0_411, 0xc0d01f60 },
  { DEVICE_SC04E_OMUAMDI,           0xc1169808 },
  { DEVICE_SCL21_KDALJD,            0xc0c71dc0 },
  { DEVICE_SH04E_01_00_02,          0xc0eed190 },
  { DEVICE_SH04E_01_00_03,          0xc0eed190 },
  { DEVICE_SOL21_9_1_D_0_395,       0xc0d030c8 },
  { DEVICE_SONYTABLET_S_RELEASE5A,  0xc06e4d18 },
  { DEVICE_SONYTABLET_P_RELEASE5A,  0xc06e6da0 },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

unsigned long int
get_ptmx_fops_address(void)
{
  device_id_t device_id = detect_device();
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
