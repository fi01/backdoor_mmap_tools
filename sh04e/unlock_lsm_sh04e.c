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

#define security_ops_01_00_02   0xc08202b8

static lsm_fix_t lsm_fixes_01_00_02[] = {
  { 0xc021bdd0, 0xc0219984 },   // ptrace_access_check
  { 0xc021bdd8, 0xc0219a1c },   // ptrace_traceme
  { 0xc021c5bc, 0xc0219de4 },   // bprm_set_creds
  { 0xc021c3e4, 0xc021bac0 },   // sb_mount
  { 0xc021c26c, 0xc021bac8 },   // sb_umount
  { 0xc021c1fc, 0xc021bad0 },   // sb_pivotroot
  { 0xc021c2d8, 0xc021bbb8 },   // path_symlink
  { 0xc021c168, 0xc021bbd8 },   // path_chmod
  { 0xc021c108, 0xc021bbe8 },   // path_chroot
  { 0xc021bde0, 0xc021a32c },   // task_fix_setuid
};

static int n_lsm_fixes_01_00_02 = sizeof (lsm_fixes_01_00_02) / sizeof (lsm_fixes_01_00_02[0]);

#define security_ops_01_00_03   0xc08202b8

static lsm_fix_t lsm_fixes_01_00_03[] = {
  { 0xc021bf00, 0xc0219ab4 },   // ptrace_access_check
  { 0xc021bf08, 0xc0219b4c },   // ptrace_traceme
  { 0xc021c6ec, 0xc0219f14 },   // bprm_set_creds
  { 0xc021c514, 0xc021bbf0 },   // sb_mount
  { 0xc021c39c, 0xc021bbf8 },   // sb_umount
  { 0xc021c32c, 0xc021bc00 },   // sb_pivotroot
  { 0xc021c408, 0xc021bce8 },   // path_symlink
  { 0xc021c298, 0xc021bd08 },   // path_chmod
  { 0xc021c238, 0xc021bd18 },   // path_chroot
  { 0xc021bf10, 0xc021a45c },   // task_fix_setuid
};

static int n_lsm_fixes_01_00_03 = sizeof (lsm_fixes_01_00_03) / sizeof (lsm_fixes_01_00_03[0]);

#define security_ops_01_00_04   0xc08202b8

static lsm_fix_t lsm_fixes_01_00_04[] = {
  { 0xc021bf18, 0xc0219acc },    // ptrace_access_check
  { 0xc021bf20, 0xc0219b64 },    // ptrace_traceme
  { 0xc021c704, 0xc0219f2c },    // bprm_set_creds
  { 0xc021c52c, 0xc021bc08 },    // sb_mount
  { 0xc021c3b4, 0xc021bc10 },    // sb_umount
  { 0xc021c344, 0xc021bc18 },    // sb_pivotroot
  { 0xc021c420, 0xc021bd00 },    // path_symlink
  { 0xc021c2b0, 0xc021bd20 },    // path_chmod
  { 0xc021c250, 0xc021bd30 },    // path_chroot
  { 0xc021bf28, 0xc021a474 },    // task_fix_setuid
};

static int n_lsm_fixes_01_00_04 = sizeof (lsm_fixes_01_00_04) / sizeof (lsm_fixes_01_00_04[0]);

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
  case DEVICE_SH04E_01_00_02:
    security_ops = security_ops_01_00_02;
    lsm_fixes = lsm_fixes_01_00_02;
    n_lsm_fixes = n_lsm_fixes_01_00_02;
    break;

  case DEVICE_SH04E_01_00_03:
    security_ops = security_ops_01_00_03;
    lsm_fixes = lsm_fixes_01_00_03;
    n_lsm_fixes = n_lsm_fixes_01_00_03;
    break;

  case DEVICE_SH04E_01_00_04:
    security_ops = security_ops_01_00_04;
    lsm_fixes = lsm_fixes_01_00_04;
    n_lsm_fixes = n_lsm_fixes_01_00_04;
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
