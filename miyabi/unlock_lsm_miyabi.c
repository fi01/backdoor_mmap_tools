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

#define ARRAY_SIZE(x)           (sizeof (x) / sizeof (x[0]))

#define SECURITY_OPS_OFFSET     3


typedef struct {
  unsigned long int lsm_func;
  unsigned long int cap_func;
} lsm_fix_t;

unsigned long int security_ops;
int n_security_ops;
lsm_fix_t *lsm_fixes;
int n_lsm_fixes;

unsigned long int unlock_module_patch_address = 0;
unsigned long int *unlock_module_patch_data = NULL;
int unlock_module_patch_data_size = 0;


#define security_ops_sbm203sh_s0024     0xc0820278
#define n_security_ops_sbm203sh_s0024   140

static lsm_fix_t lsm_fixes_sbm203sh_s0024[] = {
  { 0xc02199e4, 0xc0217598 },   // ptrace_access_check
  { 0xc02199ec, 0xc0217630 },   // ptrace_traceme
  { 0xc021a1d0, 0xc02179f8 },   // bprm_set_creds
  { 0xc0219ff8, 0xc02196d4 },   // sb_mount
  { 0xc0219e80, 0xc02196dc },   // sb_umount
  { 0xc0219e10, 0xc02196e4 },   // sb_pivotroot
  { 0xc0219eec, 0xc02197cc },   // path_symlink
  { 0xc0219d7c, 0xc02197ec },   // path_chmod
  { 0xc0219d1c, 0xc02197fc },   // path_chroot
  { 0xc02199f4, 0xc0217f40 },   // task_fix_setuid
};


#define security_ops_sh02e_02_00_03     0xc08200f8
#define n_security_ops_sh02e_02_00_03   140

static lsm_fix_t lsm_fixes_sh02e_02_00_03[] = {
  { 0xc0219a00, 0xc02175b4 },   // ptrace_access_check
  { 0xc0219a08, 0xc021764c },   // ptrace_traceme
  { 0xc021a1f4, 0xc0217a14 },   // bprm_set_creds
  { 0xc021a01c, 0xc02196f0 },   // sb_mount
  { 0xc0219e9c, 0xc02196f8 },   // sb_umount
  { 0xc0219e2c, 0xc0219700 },   // sb_pivotroot
  { 0xc0219f08, 0xc02197e8 },   // path_symlink
  { 0xc0219d98, 0xc0219808 },   // path_chmod
  { 0xc0219d38, 0xc0219818 },   // path_chroot
  { 0xc0219a10, 0xc0217f5c },   // task_fix_setuid
};


#define security_ops_sh04e_01_00_02     0xc08202b8
#define n_security_ops_sh04e_01_00_02   140

static lsm_fix_t lsm_fixes_sh04e_01_00_02[] = {
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


#define security_ops_sh04e_01_00_03     0xc08202b8
#define n_security_ops_sh04e_01_00_03   140

static lsm_fix_t lsm_fixes_sh04e_01_00_03[] = {
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


#define security_ops_sh04e_01_00_04     0xc08202b8
#define n_security_ops_sh04e_01_00_04   140

static lsm_fix_t lsm_fixes_sh04e_01_00_04[] = {
  { 0xc021bf18, 0xc0219acc },   // ptrace_access_check
  { 0xc021bf20, 0xc0219b64 },   // ptrace_traceme
  { 0xc021c704, 0xc0219f2c },   // bprm_set_creds
  { 0xc021c52c, 0xc021bc08 },   // sb_mount
  { 0xc021c3b4, 0xc021bc10 },   // sb_umount
  { 0xc021c344, 0xc021bc18 },   // sb_pivotroot
  { 0xc021c420, 0xc021bd00 },   // path_symlink
  { 0xc021c2b0, 0xc021bd20 },   // path_chmod
  { 0xc021c250, 0xc021bd30 },   // path_chroot
  { 0xc021bf28, 0xc021a474 },   // task_fix_setuid
};


#define security_ops_sh05e_01_00_05     0xc0c68108
#define n_security_ops_sh05e_01_00_05   140

static lsm_fix_t lsm_fixes_sh05e_01_00_05[] = {
  { 0xc03436bc, 0xc03418ec },   // ptrace_access_check
  { 0xc03436c4, 0xc0341868 },   // ptrace_traceme
  { 0xc0343940, 0xc0343398 },   // sb_mount
  { 0xc03436cc, 0xc03433a0 },   // sb_umount
  { 0xc0343c18, 0xc03433a8 },   // sb_pivotroot
  { 0xc0343b1c, 0xc0343490 },   // path_symlink
  { 0xc0343c70, 0xc03434c0 },   // path_chroot
};


#define security_ops_sh05e_01_00_06     0xc0c68108
#define n_security_ops_sh05e_01_00_06   140

static lsm_fix_t lsm_fixes_sh05e_01_00_06[] = {
  { 0xc0343790, 0xc03419c0 },   // ptrace_access_check
  { 0xc0343798, 0xc034193c },   // ptrace_traceme
  { 0xc03437a0, 0xc0343474 },   // sb_umount
  { 0xc0343a14, 0xc034346c },   // sb_mount
  { 0xc0343cec, 0xc034347c },   // sb_pivotroot
  { 0xc0343bf0, 0xc0343564 },   // path_symlink
  { 0xc0343d44, 0xc0343594 },   // path_chroot
};


#define security_ops_sh06e_01_00_01     0xc082d0b8
#define n_security_ops_sh06e_01_00_01   140

static lsm_fix_t lsm_fixes_sh06e_01_00_01[] = {
  { 0xc0262848, 0xc02603fc },   // ptrace_access_check
  { 0xc0262850, 0xc0260494 },   // ptrace_traceme
  { 0xc0262858, 0xc0262638 },   // path_link
  { 0xc0262860, 0xc0260da4 },   // task_fix_setuid
  { 0xc02628f8, 0xc0262650 },   // path_chmod
  { 0xc026298c, 0xc0262540 },   // sb_umount
  { 0xc02629f8, 0xc02626b4 },   // dentry_open
  { 0xc0262d94, 0xc0262660 },   // path_chroot
  { 0xc0262e14, 0xc0262548 },   // sb_pivotroot
  { 0xc0262e94, 0xc0262630 },   // path_symlink
  { 0xc0262fa8, 0xc0262538 },   // sb_mount
  { 0xc0263180, 0xc026085c },   // bprm_set_creds
};


#define security_ops_sh06e_01_00_06     0xc082d0b8
#define n_security_ops_sh06e_01_00_06   140

static lsm_fix_t lsm_fixes_sh06e_01_00_06[] = {
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


#define security_ops_sh06e_01_00_07     0xc082d0b8
#define n_security_ops_sh06e_01_00_07   140

static lsm_fix_t lsm_fixes_sh06e_01_00_07[] = {
  { 0xc026288c, 0xc0260440 },   // ptrace_access_check
  { 0xc0262894, 0xc02604d8 },   // ptrace_traceme
  { 0xc026289c, 0xc026267c },   // path_link
  { 0xc02628a4, 0xc0260de8 },   // task_fix_setuid
  { 0xc026293c, 0xc0262694 },   // path_chmod
  { 0xc02629d0, 0xc0262584 },   // sb_umount
  { 0xc0262a3c, 0xc02626f8 },   // dentry_open
  { 0xc0262dd8, 0xc02626a4 },   // path_chroot
  { 0xc0262e58, 0xc026258c },   // sb_pivotroot
  { 0xc0262ed8, 0xc0262674 },   // path_symlink
  { 0xc0262fec, 0xc026257c },   // sb_mount
  { 0xc02631c4, 0xc02608a0 },   // bprm_set_creds
};


#define unlock_module_patch_address_sh06e_01_00_07	0xc00bcc50

static unsigned long int unlock_module_patch_data_sh06e_01_00_07[] = {
  0xe3a00000,	// BL  <memcmp>   ->  MOV  R0 #0
};

#define security_ops_sh07e_01_00_03     0xc082d0b8
#define n_security_ops_sh07e_01_00_03   140

static lsm_fix_t lsm_fixes_sh07e_01_00_03[] = {
  { 0xc0262a54, 0xc0260608 },   // ptrace_access_check
  { 0xc0262a5c, 0xc02606a0 },   // ptrace_traceme
  { 0xc0262a64, 0xc0262844 },   // path_link
  { 0xc0262a6c, 0xc0260fb0 },   // task_fix_setuid
  { 0xc0262b04, 0xc026285c },   // path_chmod
  { 0xc0262b98, 0xc026274c },   // sb_umount
  { 0xc0262c04, 0xc02628c0 },   // dentry_open
  { 0xc0262fa0, 0xc026286c },   // path_chroot
  { 0xc0263020, 0xc0262754 },   // sb_pivotroot
  { 0xc02630a0, 0xc026283c },   // path_symlink
  { 0xc02631b4, 0xc0262744 },   // sb_mount
  { 0xc026338c, 0xc0260a68 },   // bprm_set_creds
};


#define security_ops_sh09d_02_00_03     0xc0720c38
#define n_security_ops_sh09d_02_00_03   174

static lsm_fix_t lsm_fixes_sh09d_02_00_03[] = {
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

#define security_ops_shl21_01_00_09     0xc0e78c64
#define n_security_ops_shl21_01_00_09   174

static lsm_fix_t lsm_fixes_shl21_01_00_09[] = {
  { 0xc0341e14, 0xc033fbbc },   // ptrace_access_check
  { 0xc0341e1c, 0xc033fb38 },   // ptrace_traceme
  { 0xc03422e4, 0xc0341a10 },   // sb_mount
  { 0xc0342284, 0xc0341a18 },   // sb_umount
  { 0xc0342120, 0xc0341a20 },   // sb_pivotroot
  { 0xc0342188, 0xc0341b08 },   // path_symlink
  { 0xc0342100, 0xc0341b38 },   // path_chroot
  { 0xc03425d8, 0xc0341d18 },   // socket_setsockopt
};


#define security_ops_shl21_01_01_02     0xc071f0f8
#define n_security_ops_shl21_01_01_02   174

static lsm_fix_t lsm_fixes_shl21_01_01_02[] = {
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


bool
unlock_lsm(void)
{
  unsigned long int *p;
  int count = 0;
  int i;

  p = backdoor_convert_to_mmaped_address((void *)security_ops);

  for (i = SECURITY_OPS_OFFSET; i < n_security_ops; i++) {
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
unlock_module(void)
{
  unsigned long int *p;
  int count = 0;
  int i;

  if (!unlock_module_patch_address) {
    return false;
  }

  p = backdoor_convert_to_mmaped_address((void *)unlock_module_patch_address);

  for (i = 0; i < unlock_module_patch_data_size; i++) {
    p[i] = unlock_module_patch_data[i];
  }

  printf("  kernel module is enabled.\n");

  return true;
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

  if (unlock_module_patch_address) {
    ret = unlock_module() && ret;
  }

  backdoor_close_mmap();
  return ret;
}

int
main(int argc, char **argv)
{
  switch (detect_device()) {
  case DEVICE_SBM203SH_S0024:
    security_ops = security_ops_sbm203sh_s0024;
    n_security_ops = n_security_ops_sbm203sh_s0024;
    lsm_fixes = lsm_fixes_sbm203sh_s0024;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_sbm203sh_s0024);
    break;

  case DEVICE_SH02E_02_00_03:
    security_ops = security_ops_sh02e_02_00_03;
    n_security_ops = n_security_ops_sh02e_02_00_03;
    lsm_fixes = lsm_fixes_sh02e_02_00_03;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_sh02e_02_00_03);
    break;

  case DEVICE_SH04E_01_00_02:
    security_ops = security_ops_sh04e_01_00_02;
    n_security_ops = n_security_ops_sh04e_01_00_02;
    lsm_fixes = lsm_fixes_sh04e_01_00_02;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_sh04e_01_00_02);
    break;

  case DEVICE_SH04E_01_00_03:
    security_ops = security_ops_sh04e_01_00_03;
    n_security_ops = n_security_ops_sh04e_01_00_03;
    lsm_fixes = lsm_fixes_sh04e_01_00_03;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_sh04e_01_00_03);
    break;

  case DEVICE_SH04E_01_00_04:
    security_ops = security_ops_sh04e_01_00_04;
    n_security_ops = n_security_ops_sh04e_01_00_04;
    lsm_fixes = lsm_fixes_sh04e_01_00_04;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_sh04e_01_00_04);
    break;

  case DEVICE_SH05E_01_00_05:
    security_ops = security_ops_sh05e_01_00_05;
    n_security_ops = n_security_ops_sh05e_01_00_05;
    lsm_fixes = lsm_fixes_sh05e_01_00_05;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_sh05e_01_00_05);
    break;

  case DEVICE_SH05E_01_00_06:
    security_ops = security_ops_sh05e_01_00_06;
    n_security_ops = n_security_ops_sh05e_01_00_06;
    lsm_fixes = lsm_fixes_sh05e_01_00_06;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_sh05e_01_00_06);
    break;

  case DEVICE_SH09D_02_00_03:
    security_ops = security_ops_sh09d_02_00_03;
    n_security_ops = n_security_ops_sh09d_02_00_03;
    lsm_fixes = lsm_fixes_sh09d_02_00_03;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_sh09d_02_00_03);
    break;

  case DEVICE_SH06E_01_00_01:
    security_ops = security_ops_sh06e_01_00_01;
    n_security_ops = n_security_ops_sh06e_01_00_01;
    lsm_fixes = lsm_fixes_sh06e_01_00_01;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_sh06e_01_00_01);
    break;

  case DEVICE_SH06E_01_00_06:
    security_ops = security_ops_sh06e_01_00_06;
    n_security_ops = n_security_ops_sh06e_01_00_06;
    lsm_fixes = lsm_fixes_sh06e_01_00_06;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_sh06e_01_00_06);
    break;

  case DEVICE_SH06E_01_00_07:
    security_ops = security_ops_sh06e_01_00_07;
    n_security_ops = n_security_ops_sh06e_01_00_07;
    lsm_fixes = lsm_fixes_sh06e_01_00_07;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_sh06e_01_00_07);

    unlock_module_patch_address = unlock_module_patch_address_sh06e_01_00_07;
    unlock_module_patch_data = unlock_module_patch_data_sh06e_01_00_07;
    unlock_module_patch_data_size = ARRAY_SIZE(unlock_module_patch_data_sh06e_01_00_07);
    break;

  case DEVICE_SH07E_01_00_03:
    security_ops = security_ops_sh07e_01_00_03;
    n_security_ops = n_security_ops_sh07e_01_00_03;
    lsm_fixes = lsm_fixes_sh07e_01_00_03;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_sh07e_01_00_03);
    break;

  case DEVICE_SHL21_01_00_09:
    security_ops = security_ops_shl21_01_00_09;
    n_security_ops = n_security_ops_shl21_01_00_09;
    lsm_fixes = lsm_fixes_shl21_01_00_09;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_shl21_01_00_09);
    break;

  case DEVICE_SHL21_01_01_02:
    security_ops = security_ops_shl21_01_01_02;
    n_security_ops = n_security_ops_shl21_01_01_02;
    lsm_fixes = lsm_fixes_shl21_01_01_02;
    n_lsm_fixes = ARRAY_SIZE(lsm_fixes_shl21_01_01_02);
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
