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

#define security_ops_01_00_06   0xc082d0b8

static lsm_fix_t lsm_fixes_01_00_06[] = {
 { 0xc0262838, 0xc02603ec },   // ptrace_access_check
 { 0xc0262840, 0xc0260484 },   // ptrace_traceme
 { 0xc0262848, 0xc0262628 },   // path_link
 { 0xc0262850, 0xc0260d94 },   // task_fix_setuid
 { 0xc02628e8, 0xc0262640 },   // path_chmod
 { 0xc026297c, 0xc0262530 },   // sb_umount
 { 0xc02629e8, 0xc02626a4 },   // dentry_open
 { 0xc0262d84, 0xc0262650 },   // path_chroot
 { 0xc0262e04, 0xc0262538 },   // sb_pivotroot
 { 0xc0262e84, 0xc0262620 },   // path_symlink
 { 0xc0262f98, 0xc0262528 },   // sb_mount
 { 0xc0263170, 0xc026084c },   // bprm_set_creds
};

static int n_lsm_fixes_01_00_06 = sizeof (lsm_fixes_01_00_06) / sizeof (lsm_fixes_01_00_06[0]);

bool
unlock_lsm(void)
{
  unsigned long int *p;
  int count = 0;
  int i;

  p = backdoor_convert_to_mmaped_address((void *)security_ops);

  if (strcmp("miyabi", (char *)p) != 0) {
    printf("security_ops is not found.\n");
    return false;
  }

  printf("Found security_ops!\n");

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
  case DEVICE_SH06E_01_00_06:
    security_ops = security_ops_01_00_06;
    lsm_fixes = lsm_fixes_01_00_06;
    n_lsm_fixes = n_lsm_fixes_01_00_06;
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
