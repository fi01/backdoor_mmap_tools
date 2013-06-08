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

#define ARRAY_SIZE(x)  (sizeof (x) / sizeof ((x)[0]))

#define reset_security_ops_address                0xc027ec94

#define default_security_ops_address              0xc0fa6804
#define security_ops_address                      0xc1150630

static const unsigned long int check_reset_security_ops[] = {
  0xe59f2008, //      LDR     R2, =0xc0fa6804 [$c027eca4] ; default_security_ops
  0xe59f3008, //      LDR     R3, =0xc1150630 [$c027eca8] ; security_ops
  0xe5832000, //      STR     R2, [R3]
  0xe12fff1e, //      BX      LR
  default_security_ops_address,
  security_ops_address,
};

#define sec_restrict_uid_address                  0xc00859ac

static const unsigned long int check_sec_restrict_uid[] = {
  0xe92d40f7, //      STMPW   [SP], { R0-R2, R4-R7, LR }
  0xe59f012c, //      LDR     R0, =0xc0f06040 [$c0085ae4] ; tasklist_lock
  0xeb1de652, //      BL      $c07ff304                   ; _raw_read_lock
};

#define sec_check_execpath_address                0xc0011550

static const unsigned long int check_sec_check_execpath[] = {
  0xe2503000, //      SUBS    R3, R0, #$0
  0xe92d41f0, //      STMPW   [SP], { R4-R8, LR }
  0xe1a06001, //      MOV     R6, R1
  0x01a06003, //      MOVEQ   R6, R3
  0x0a000031, //      BEQ     $c001162c
  0xeb017e97, //      BL      $c0070fc8                   ; get_mm_exe_file
};

#define sys_execve_address                        0xc00116b0

static const unsigned long int check_sys_execve[] = {
  0xe92d4ff0, //      STMPW   [SP], { R4-R11, LR }
  0xe24dd014, //      SUB     SP, SP, #$14
  0xe1a05003, //      MOV     R5, R3
  0xe1a06002, //      MOV     R6, R2
  0xe58d100c, //      STR     R1, [SP, #$c]
  0xeb04b560, //      BL      $c013ec4c                   ; getname
  0xe3700a01, //      CMNS    R0, #$1000
  0xe1a04000, //      MOV     R4, R0
  0x81a05000, //      MOVHI   R5, R0
  0x8a00009e, //      BHI     $c0011954                   ; IS_ERR(filename)
  0xe1a0200d, //      MOV     R2, SP
  0xe3c23d7f, //      BIC     R3, R2, #$1fc0
  0xe3c3303f, //      BIC     R3, R3, #$3f
  0xe593300c, //      LDR     R3, [R3, #$c]
  0xe5933204, //      LDR     R3, [R3, #$204]
  0xe5932004, //      LDR     R2, [R3, #$4]
  0xe3520000, //      CMPS    R2, #$0
  0x0a00000e, //      BEQ     $c0011734
  0xe5932008, //      LDR     R2, [R3, #$8]
  0xe3520000, //      CMPS    R2, #$0
  0x0a00000b, //      BEQ     $c0011734
};

#define DEFINE_CHECK(name)  { name##_address, check_##name, sizeof(check_##name) }

struct check_code_t {
  unsigned long int addr;
  const unsigned long int *expected;
  size_t size;
};

static struct check_code_t check_code[] =
{
  DEFINE_CHECK(reset_security_ops),
  DEFINE_CHECK(sec_restrict_uid),
  DEFINE_CHECK(sec_check_execpath),
  DEFINE_CHECK(sys_execve),
};

static bool
check_unlock_code(void)
{
  unsigned long int *p;
  int pos;
  bool ret = true;

  for (pos = 0; pos < ARRAY_SIZE(check_code); pos++) {
    p = backdoor_convert_to_mmaped_address((void *)check_code[pos].addr);

    if (memcmp(p, check_code[pos].expected, check_code[pos].size) != 0) {
      int i;

      printf("kernel code doesn't match at 0x%08x !!\n", check_code[pos].addr);
      for (i = 0; i < check_code[pos].size / sizeof (check_code[pos].expected[0]); i++) {
        printf("  0x%08x\n", p[i]);
      }

      printf("\n");

      ret = false;
    }
  }

  return ret;
}

static const unsigned long int return_zero[] = {
  0xe3a00000, //    MOV     R0, #$0
  0xe12fff1e, //    BX      LR
};

static const unsigned long int patched_sys_execve[] = {
  0xe92d4ff0, //      STMPW   [SP], { R4-R11, LR }
  0xe24dd014, //      SUB     SP, SP, #$14
  0xe1a05003, //      MOV     R5, R3
  0xe1a06002, //      MOV     R6, R2
  0xe58d100c, //      STR     R1, [SP, #$c]
  0xeb04b560, //      BL      $c013ec4c                   ; getname
  0xe3700a01, //      CMNS    R0, #$1000
  0xe1a04000, //      MOV     R4, R0
  0x81a05000, //      MOVHI   R5, R0
  0x8a00009e, //      BHI     $c0011954
  0xe1a03005, //      MOV     R3, R5
  0xe1a00004, //      MOV     R0, R4
  0xe59d100c, //      LDR     R1, [SP, #$c]
  0xe1a02006, //      MOV     R2, R6
  0xeb04a6b8, //      BL      $c013b1d0                   ; do_execve
  0xe1a05000, //      MOV     R5, R0
  0xe1a00004, //      MOV     R0, R4
  0xeb04b557, //      BL      $c013ec58                   ; putname
  0xe1a00005, //      MOV     R0, R5
  0xe28dd014, //      ADD     SP, SP, #$14
  0xe8bd8ff0, //      LDMUW   [SP], { R4-R11, PC }
};

static void
do_patch(void)
{
  unsigned long int *p;

  p = backdoor_convert_to_mmaped_address((void *)sec_restrict_uid_address);
  memcpy(p, return_zero, sizeof return_zero);

  p = backdoor_convert_to_mmaped_address((void *)sec_check_execpath_address);
  memcpy(p, return_zero, sizeof return_zero);

  p = backdoor_convert_to_mmaped_address((void *)sys_execve_address);
  memcpy(p, patched_sys_execve, sizeof patched_sys_execve);

  p = backdoor_convert_to_mmaped_address((void *)security_ops_address);
  *p = default_security_ops_address;
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

  if (check_unlock_code()) {
    do_patch();
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
