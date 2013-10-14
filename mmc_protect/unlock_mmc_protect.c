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

//#define DISABLE_UNLOCK_MMC_SYSTEM_WRITE

#define mmc_protect_part_sbm203sh_s0024 0xc08546cc
#define mmc_protect_part_sh02e_02_00_03 0xc0853774
#define mmc_protect_part_sh04e_01_00_02 0xc0852b94
#define mmc_protect_part_sh04e_01_00_03 0xc0852b94
#define mmc_protect_part_sh04e_01_00_04 0xc0852b84
#define mmc_protect_part_sh05e_01_00_05 0xc0821424
#define mmc_protect_part_sh05e_01_00_06 0xc08216e4
#define mmc_protect_part_sh06e_01_00_06 0xc086aa5c
#define mmc_protect_part_sh06e_01_00_07 0xc086aa54
#define mmc_protect_part_sh07e_01_00_03 0xc086968c
#define mmc_protect_part_sh09d_02_00_03 0xc075262c
#define mmc_protect_part_shl21_01_00_09 0xc09b6e58
#define mmc_protect_part_shl21_01_01_02 0xc074feac

#define MMC_SYSTEM_PARTITION_TYPE1      15
#define MMC_SYSTEM_PARTITION_TYPE2      12

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

static unsigned long int mmc_protect_part;
static const struct mmc_protect_inf *check_mmc_protect_part;
static int n_mmc_protect_part;
static int mmc_system_partition;

bool
unlock_mmc_protect_part(void)
{
  struct mmc_protect_inf *p;
  int count_readable = 0;
  int count_writable = 0;
  int i;

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
do_unlock(void)
{
  bool ret;

  if (!backdoor_open_mmap()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));
    printf("Run 'install_backdoor' first\n");

    return false;
  }

  ret = unlock_mmc_protect_part();

  backdoor_close_mmap();
  return ret;
}

int
main(int argc, char **argv)
{
  check_mmc_protect_part = check_mmc_protect_part_type1;
  n_mmc_protect_part = n_mmc_protect_part_type1;
  mmc_system_partition = MMC_SYSTEM_PARTITION_TYPE1;

  switch (detect_device()) {
  case DEVICE_SBM203SH_S0024:
    mmc_protect_part = mmc_protect_part_sbm203sh_s0024;
    break;

  case DEVICE_SH04E_01_00_02:
    mmc_protect_part = mmc_protect_part_sh04e_01_00_02;
    break;

  case DEVICE_SH04E_01_00_03:
    mmc_protect_part = mmc_protect_part_sh04e_01_00_03;
    break;

  case DEVICE_SH04E_01_00_04:
    mmc_protect_part = mmc_protect_part_sh04e_01_00_04;
    break;

  case DEVICE_SH05E_01_00_05:
    mmc_protect_part = mmc_protect_part_sh05e_01_00_05;
    check_mmc_protect_part = check_mmc_protect_part_type2;
    n_mmc_protect_part = n_mmc_protect_part_type2;
    mmc_system_partition = MMC_SYSTEM_PARTITION_TYPE2;
    break;

  case DEVICE_SH05E_01_00_06:
    mmc_protect_part = mmc_protect_part_sh05e_01_00_06;
    check_mmc_protect_part = check_mmc_protect_part_type2;
    n_mmc_protect_part = n_mmc_protect_part_type2;
    mmc_system_partition = MMC_SYSTEM_PARTITION_TYPE2;
    break;

  case DEVICE_SH06E_01_00_06:
    mmc_protect_part = mmc_protect_part_sh06e_01_00_06;
    break;

  case DEVICE_SH06E_01_00_07:
    mmc_protect_part = mmc_protect_part_sh06e_01_00_07;
    break;

  case DEVICE_SH07E_01_00_03:
    mmc_protect_part = mmc_protect_part_sh07e_01_00_03;
    break;

  case DEVICE_SH09D_02_00_03:
    check_mmc_protect_part = check_mmc_protect_part_type2;
    n_mmc_protect_part = n_mmc_protect_part_type2;
    mmc_protect_part = mmc_protect_part_sh09d_02_00_03;
    mmc_system_partition = MMC_SYSTEM_PARTITION_TYPE2;
    break;

  case DEVICE_SHL21_01_00_09:
    check_mmc_protect_part = check_mmc_protect_part_type2;
    n_mmc_protect_part = n_mmc_protect_part_type2;
    mmc_protect_part = mmc_protect_part_shl21_01_00_09;
    mmc_system_partition = MMC_SYSTEM_PARTITION_TYPE2;
    break;

  case DEVICE_SHL21_01_01_02:
    check_mmc_protect_part = check_mmc_protect_part_type2;
    n_mmc_protect_part = n_mmc_protect_part_type2;
    mmc_protect_part = mmc_protect_part_shl21_01_01_02;
    mmc_system_partition = MMC_SYSTEM_PARTITION_TYPE2;
    break;

  default:
    print_reason_device_not_supported();
    return 1;
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
