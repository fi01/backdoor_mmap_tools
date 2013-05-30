#include <stdio.h>
#include <sys/system_properties.h>
#include "detect_device.h"

typedef struct _supported_device {
  int device_id;
  const char *device;
  const char *build_id;
  const char *build_ver_inc;
} supported_device;

static supported_device supported_devices[] = {
  { DEV_F11D_V24R40A,       "F-11D",            "V24R40A",            NULL },
  { DEV_IS17SH_01_00_04,    "IS17SH",           "01.00.04",           NULL },
  { DEV_ISW12K_010_0_3000,  "URBANO PROGRESSO", "010.0.3000",         NULL },
  { DEV_SCL21_KDALJD,       "SCL21",            "IMM76D.SCL21KDALJD", NULL },
  { DEV_ISW13F_V69R51I,     "ISW13F",           "V69R51I",            NULL },
  { DEV_SONYTABS_RELEASE5A, "Sony Tablet S",    "TISU0143",           NULL },
  { DEV_SONYTABP_RELEASE5A, "Sony Tablet P",    "TISU0144",           NULL },
  { DEV_SH04E_01_00_02,     "SH-04E",           "01.00.02",           NULL },
  { DEV_SOL21_9_1_D_0_395,  "SOL21",            "9.1.D.0.395",        NULL },
  { DEV_HTL21_JRO03C,       "HTL21",            "JRO03C",             NULL },
  { DEV_L06D_V10k,          "L-06D",            "IMM76D",             "L06DV10k.4821c158" },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

int
detect_device(void)
{
  int i;
  char device[PROP_VALUE_MAX];
  char build_id[PROP_VALUE_MAX];
  char build_ver_inc[PROP_VALUE_MAX];

  __system_property_get("ro.product.model", device);
  __system_property_get("ro.build.display.id", build_id);
  __system_property_get("ro.build.version.incremental", build_ver_inc);

  for (i = 0; i < n_supported_devices; i++) {
    if (!strcmp(device, supported_devices[i].device) &&
        !strcmp(build_id, supported_devices[i].build_id)) {
      if (!supported_devices[i].build_ver_inc) {
        return supported_devices[i].device_id;
      }

      if (!strcmp(build_ver_inc, supported_devices[i].build_ver_inc)) {
        return supported_devices[i].device_id;
      }
    }
  }

  return DEV_NOT_SUPPORTED;
}

int
print_reason_device_not_supported(void)
{
  char device[PROP_VALUE_MAX];
  char build_id[PROP_VALUE_MAX];

  __system_property_get("ro.product.model", device);
  __system_property_get("ro.build.display.id", build_id);

  printf("%s (%s) is not supported.\n", device, build_id);
}
