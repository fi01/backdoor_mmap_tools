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

#define reset_security_ops_address                              0xc031311c

#define default_security_ops_address                            0xc0bc43d4
#define security_ops_address                                    0xc109cb08

static const unsigned long int check_reset_security_ops[] = {
  0xe59f2008, //      LDR     R2, =0xc0bc43d4 [$c031312c]       ; default_security_ops
  0xe59f3008, //      LDR     R3, =0xc109cb08 [$c0313130]       ; security_ops
  0xe5832000, //      STR     R2, [R3]
  0xe12fff1e, //      BX      LR
  default_security_ops_address,
  security_ops_address,
};

//TODO: remove MMC_CAP_ERASE
#if 0
  0xe3833c06, //      ORR     R3, R3, #$600                     ; MMC_CAP_WAIT_WHILE_BUSY=$0200, MMC_CAP_ERASE=$0400
  0xe3832006, //      ORR     R2, R3, #$6
  0xe5852188, //      STR     R2, [R5, #$188]
#endif

#define check_mmc_blk_probe_enable_boot_partition_address 0xc05618b4

#define mmc_blk_probe_enable_boot_partition_address       0xc05618b8

#define mmc_blk_probe_enable_boot_partition_patch_address 0xc05618c0
#define mmc_blk_probe_enable_boot_partition_patch_value   0xe3a0c000    // MOV     R12, #$0

static const unsigned long int check_mmc_blk_probe_enable_boot_partition[] = {
  0xe592c18c, //      LDR     R12, [R2, #$18c]
  0xe21cc001, //      ANDS    R12, R12, #$1                     ; R12 = host->caps2 & MMC_CAP2_BOOTPART_NOACC;
  0x1a000016, //      BNE     $c0561920
  0xe58dc004, //      STR     R12, [SP, #$4]                    ; R12 = 0 !!
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
  DEFINE_CHECK(mmc_blk_probe_enable_boot_partition),
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

      printf("kernel code doesn't match at 0x%08lx !!\n", check_code[pos].addr);
      for (i = 0; i < check_code[pos].size / sizeof (check_code[pos].expected[0]); i++) {
        printf("  0x%08lx\n", p[i]);
      }

      printf("\n");

      ret = false;
    }
  }

  return ret;
}

static void
do_patch(void)
{
  unsigned long int *p;

  p = backdoor_convert_to_mmaped_address((void *)mmc_blk_probe_enable_boot_partition_patch_address);
  *p = mmc_blk_probe_enable_boot_partition_patch_value;

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
