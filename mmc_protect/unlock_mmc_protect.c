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

//#define DISABLE_UNLOCK_MMC_SYSTEM_WRITE

#define mmc_protect_part_sbm203sh_s0024 0xc08546cc
#define mmc_protect_part_sh02e_02_00_03 0xc0853774
#define mmc_protect_part_sh04e_01_00_02 0xc0852b94
#define mmc_protect_part_sh04e_01_00_03 0xc0852b94
#define mmc_protect_part_sh04e_01_00_04 0xc0852b84
#define mmc_protect_part_sh05e_01_00_05 0xc0821424
#define mmc_protect_part_sh05e_01_00_06 0xc08216e4
#define mmc_protect_part_sh06e_01_00_01 0xc086aa1c
#define mmc_protect_part_sh06e_01_00_05 0xc086aa54
#define mmc_protect_part_sh06e_01_00_06 0xc086aa5c
#define mmc_protect_part_sh06e_01_00_07 0xc086aa54
#define mmc_protect_part_sh07e_01_00_03 0xc086968c
#define mmc_protect_part_sh09d_02_00_03 0xc075262c
#define mmc_protect_part_shl21_01_00_09 0xc09b6e58
#define mmc_protect_part_shl21_01_01_02 0xc074feac

#define ARRAY_SIZE(n)	(sizeof (n) / sizeof ((n)[0]))

typedef enum {
  MMC_PROTECT_PART_TYPE_UNKNOWN = 0,
  MMC_PROTECT_PART_TYPE1 = 1,
  MMC_PROTECT_PART_TYPE2,
  MMC_PROTECT_PART_TYPE3,
} mmc_protect_part_type_t;

#define MMC_SYSTEM_PARTITION_TYPE1      15
#define MMC_SYSTEM_PARTITION_TYPE2      12
#define MMC_SYSTEM_PARTITION_TYPE3      17

struct mmc_protect_inf {
  unsigned long int partition;
  unsigned long int protect;
};

#define MMC_NO_PROTECT          0x00
#define MMC_PROTECT_READ        0x01
#define MMC_PROTECT_WRITE       0x02

static const struct mmc_protect_inf check_mmc_protect_part_type1[] = {
  { 2,                       MMC_PROTECT_WRITE    },
  { 3,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 4,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 5,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 6,                       MMC_PROTECT_WRITE    },
  { 7,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 8,                       MMC_PROTECT_WRITE    },
  { 9,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {10,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {11,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {12,                       MMC_PROTECT_WRITE    },
  {13,                       MMC_PROTECT_WRITE    },
  {15,                       MMC_PROTECT_WRITE    },
};

static int n_mmc_protect_part_type1 = sizeof (check_mmc_protect_part_type1) / sizeof (check_mmc_protect_part_type1[0]);

static const struct mmc_protect_inf check_mmc_protect_part_type2[] = {
  { 1,                       MMC_PROTECT_WRITE    },
  { 2,                       MMC_PROTECT_WRITE    },
  { 3,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 4,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 5,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 6,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 8,                       MMC_PROTECT_WRITE    },
  { 9,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {10,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {11,                       MMC_PROTECT_WRITE    },
  {12,                       MMC_PROTECT_WRITE    },
  {13,                       MMC_PROTECT_WRITE    },
  {14,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
};

static int n_mmc_protect_part_type2 = sizeof (check_mmc_protect_part_type2) / sizeof (check_mmc_protect_part_type2[0]);

static const struct mmc_protect_inf check_mmc_protect_part_type3[] = {
  { 2,                       MMC_PROTECT_WRITE    },
  { 3,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 4,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 5,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 6,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 7,                       MMC_PROTECT_WRITE    },
  { 8,                       MMC_PROTECT_WRITE    },
  { 9,                       MMC_PROTECT_WRITE    },
  {10,                       MMC_PROTECT_WRITE    },
  {11,                       MMC_PROTECT_WRITE    },
  {12,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {13,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {14,                       MMC_PROTECT_WRITE    },
  {15,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {17,                       MMC_PROTECT_WRITE    },
};

static int n_mmc_protect_part_type3 = sizeof (check_mmc_protect_part_type3) / sizeof (check_mmc_protect_part_type3[0]);

static unsigned long int mmc_protect_part;
static mmc_protect_part_type_t mmc_protect_part_type;

bool
unlock_mmc_protect_part(void)
{
  const struct mmc_protect_inf *check_mmc_protect_part;
  int n_mmc_protect_part;
  int mmc_system_partition;
  struct mmc_protect_inf *p;
  int count_readable = 0;
  int count_writable = 0;
  int i;

  switch (mmc_protect_part_type) {
  case MMC_PROTECT_PART_TYPE1:
    check_mmc_protect_part = check_mmc_protect_part_type1;
    n_mmc_protect_part = n_mmc_protect_part_type1;
    mmc_system_partition = MMC_SYSTEM_PARTITION_TYPE1;
    break;

  case MMC_PROTECT_PART_TYPE2:
    check_mmc_protect_part = check_mmc_protect_part_type2;
    n_mmc_protect_part = n_mmc_protect_part_type2;
    mmc_system_partition = MMC_SYSTEM_PARTITION_TYPE2;
    break;

  case MMC_PROTECT_PART_TYPE3:
    check_mmc_protect_part = check_mmc_protect_part_type3;
    n_mmc_protect_part = n_mmc_protect_part_type3;
    mmc_system_partition = MMC_SYSTEM_PARTITION_TYPE3;
    break;

  default:
    return false;
  }

  p = backdoor_convert_to_mmaped_address((void *)mmc_protect_part);

  if (p[0].partition == 0) {
    p++;
  }

  for (i = 0; i < n_mmc_protect_part; i++) {
    if (p[i].partition != check_mmc_protect_part[i].partition) {
      printf("mmc_protect_part is not found.\n");
      return false;
    }
  }

  printf("Found mmc_protect_part!\n");

  for (i = 0; i < n_mmc_protect_part; i++) {
    if (p[i].protect & MMC_PROTECT_READ) {
      p[i].protect &= ~MMC_PROTECT_READ;
      count_readable++;
    }

    if ((p[i].protect & MMC_PROTECT_WRITE)) {
#ifndef DISABLE_UNLOCK_MMC_SYSTEM_WRITE
      if (p[i].partition == mmc_system_partition) {
        p[i].protect &= ~MMC_PROTECT_WRITE;
        count_writable++;
      }
#endif /* DISABLE_UNLOCK_MMC_SYSTEM_WRITE */
    }
  }

  printf("  %d partitions are fixed to readable.\n", count_readable);
  printf("  %d partitions are fixed to writable.\n", count_writable);

  return true;
}

static bool
detect_mmc_protect(void)
{
  typedef struct {
    mmc_protect_part_type_t type;
    const struct mmc_protect_inf *inf;
    int num;
  } check_t;

  check_t check[] = {
    { MMC_PROTECT_PART_TYPE1, check_mmc_protect_part_type1, n_mmc_protect_part_type1 },
    { MMC_PROTECT_PART_TYPE2, check_mmc_protect_part_type2, n_mmc_protect_part_type2 },
    { MMC_PROTECT_PART_TYPE3, check_mmc_protect_part_type3, n_mmc_protect_part_type3 },
  };

  kallsyms *info;
  unsigned long int addr;
  const struct mmc_protect_inf *p;
  bool ret = false;
  int i;

  info = kallsyms_in_memory_init((void *)BACKDOOR_MMAP_ADDRESS, BACKDOOR_MMAP_SIZE);
  if (info == NULL) {
    printf("kallsyms_in_memory_init(): failed\n");
    return false;
  }

  addr = kallsyms_in_memory_lookup_name(info, "mmc_protect_part");
  if (!addr) {
    goto error_exit;
  }

  printf("Found: mmc_protect_part = 0x%08x\n", addr);

  p = backdoor_convert_to_mmaped_address((void *)addr);

  if (p[0].partition == 0) {
    p++;
  }

  for (i = 0; i < ARRAY_SIZE(check); i++) {
    int n;

    for (n = 0; n < check[i].num; n++) {
      if (p[n].partition != check[i].inf[n].partition) {
        break;
      }

      if (p[n].protect & ~(MMC_PROTECT_READ | MMC_PROTECT_WRITE)) {
        break;
      }
    }

    if (n == check[i].num) {
      printf("Detect partition type: %d\n", check[i].type);

      for (n = 0; n < check[i].num; n++) {
        printf("#%d: partiton %2d: protect %d\n", n, p[n].partition, p[n].protect);
      }

      device_set_symbol_address(DEVICE_SYMBOL(mmc_protect_part), addr);
      device_set_symbol_address(DEVICE_SYMBOL(mmc_protect.part_type),  check[i].type);

      ret = true;
      break;
    }
  }

error_exit:
  kallsyms_in_memory_free(info);
  return ret;
}

static bool
setup_param_from_database(void)
{
  int i;

  if (mmc_protect_part) {
    if (mmc_protect_part_type == MMC_PROTECT_PART_TYPE1
     || mmc_protect_part_type == MMC_PROTECT_PART_TYPE2
     || mmc_protect_part_type == MMC_PROTECT_PART_TYPE3) {
      return true;
    }
  }

  mmc_protect_part = device_get_symbol_address(DEVICE_SYMBOL(mmc_protect_part));
  if (!mmc_protect_part) {
    detect_mmc_protect();

    mmc_protect_part = device_get_symbol_address(DEVICE_SYMBOL(mmc_protect_part));
  }

  mmc_protect_part_type = device_get_symbol_address(DEVICE_SYMBOL(mmc_protect.part_type));

  if (mmc_protect_part) {
    if (mmc_protect_part_type == MMC_PROTECT_PART_TYPE1
     || mmc_protect_part_type == MMC_PROTECT_PART_TYPE2
     || mmc_protect_part_type == MMC_PROTECT_PART_TYPE3) {
      return true;
    }
  }

  mmc_protect_part = 0;
  mmc_protect_part_type = MMC_PROTECT_PART_TYPE_UNKNOWN;

  return false;
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

  if (!setup_param_from_database()) {
    backdoor_close_mmap();

    print_reason_device_not_supported();

    return false;
  }

  ret = unlock_mmc_protect_part();

  backdoor_close_mmap();
  return ret;
}

int
main(int argc, char **argv)
{
  switch (detect_device()) {
  case DEVICE_SBM203SH_S0024:
    mmc_protect_part = mmc_protect_part_sbm203sh_s0024;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE1;
    break;

  case DEVICE_SH04E_01_00_02:
    mmc_protect_part = mmc_protect_part_sh04e_01_00_02;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE1;
    break;

  case DEVICE_SH04E_01_00_03:
    mmc_protect_part = mmc_protect_part_sh04e_01_00_03;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE1;
    break;

  case DEVICE_SH04E_01_00_04:
    mmc_protect_part = mmc_protect_part_sh04e_01_00_04;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE1;
    break;

  case DEVICE_SH05E_01_00_05:
    mmc_protect_part = mmc_protect_part_sh05e_01_00_05;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE2;
    break;

  case DEVICE_SH05E_01_00_06:
    mmc_protect_part = mmc_protect_part_sh05e_01_00_06;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE2;
    break;

  case DEVICE_SH06E_01_00_01:
    mmc_protect_part = mmc_protect_part_sh06e_01_00_01;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE1;
    break;

  case DEVICE_SH06E_01_00_06:
    mmc_protect_part = mmc_protect_part_sh06e_01_00_06;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE1;
    break;

  case DEVICE_SH06E_01_00_07:
    mmc_protect_part = mmc_protect_part_sh06e_01_00_07;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE1;
    break;

  case DEVICE_SH07E_01_00_03:
    mmc_protect_part = mmc_protect_part_sh07e_01_00_03;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE1;
    break;

  case DEVICE_SH09D_02_00_03:
    mmc_protect_part = mmc_protect_part_sh09d_02_00_03;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE2;
    break;

  case DEVICE_SHL21_01_00_09:
    mmc_protect_part = mmc_protect_part_shl21_01_00_09;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE2;
    break;

  case DEVICE_SHL21_01_01_02:
    mmc_protect_part = mmc_protect_part_shl21_01_01_02;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE2;
    break;

  default:
    mmc_protect_part = 0;
    mmc_protect_part_type = MMC_PROTECT_PART_TYPE_UNKNOWN;
  }

  if (!do_unlock()) {
    printf("Failed to unlock MMC protect.\n");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
