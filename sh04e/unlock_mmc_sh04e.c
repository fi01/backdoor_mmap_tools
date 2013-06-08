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

#define mmc_protect_part        0xc0852b94

#define MMC_BOOT_PARTITION      11
#define MMC_RECOVERY_PARTITION  12
#define MMC_SYSTEM_PARTITION    15

struct mmc_protect_inf {
  unsigned long int partition;
  unsigned long int protect;
};

#define MMC_NO_PROTECT          0x00
#define MMC_PROTECT_READ        0x01
#define MMC_PROTECT_WRITE       0x02

static const struct mmc_protect_inf check_mmc_protect_part[] = {
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

static int n_mmc_protect_part = sizeof (check_mmc_protect_part) / sizeof (check_mmc_protect_part[0]);

bool
unlock_mmc_protect_part(void)
{
  struct mmc_protect_inf *p;
  int count_readable = 0;
  int count_writable = 0;
  int i;

  p = backdoor_convert_to_mmaped_address((void *)mmc_protect_part);

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

#ifndef DISABLE_UNLOCK_MMC_SYSTEM_WRITE
    if (p[i].protect & MMC_PROTECT_WRITE) {
      switch (p[i].partition) {
      case MMC_SYSTEM_PARTITION:
        p[i].protect &= ~MMC_PROTECT_WRITE;
        count_writable++;
      }
    }
#endif
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
  if (!do_unlock()) {
    printf("Failed to unlock MMC protect.\n");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
