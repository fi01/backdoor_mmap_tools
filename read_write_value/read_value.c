#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "device_database/device_database.h"
#include "backdoor_mmap.h"


static void usage(const char *name)
{
  printf("usege: %s address\n", name);
  exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
  unsigned long *p;
  unsigned long address;
  char *endp;

  if (!backdoor_open_mmap()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));
    printf("Run 'install_backdoor' first\n");

    exit(EXIT_FAILURE);
  }

  if (argc != 2) {
    usage(argv[0]);
  }

  address = strtoul(argv[1], &endp, 0);
  if (*endp != '\0') {
    printf("Wrong address: %s\n", argv[1]);
    usage(argv[0]);
  }

  p = backdoor_convert_to_mmaped_address((void *)address);
  printf("value = 0x%08lx\n", *p);

  backdoor_close_mmap();

  exit(EXIT_SUCCESS);

exit_failure:
  backdoor_close_mmap();
  exit(EXIT_FAILURE);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
