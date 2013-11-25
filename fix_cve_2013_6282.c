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
#include "libkallsyms/kallsyms_in_memory.h"
#include "backdoor_mmap.h"
#include "ptmx.h"


#define ARRAY_SIZE(n)   (sizeof (n) / sizeof (*(n)))


static unsigned int vul__get_user_2[] = {
  0xe4d02001,   //     LDRB    R2, [R0], #$1
  0xe5d03000,   //     LDRB    R3, [R0]
  0xe1822403,   //     ORR     R2, R2, R3 ,LSL #8
  0xe3a00000,   //     MOV     R0, #$0
  0xe1a0f00e,   //     MOV     PC, LR
};

static unsigned int vul__get_user_bad[] = {
  0xe3a02000,   //     MOV     R2, #$0
  0xe3e0000d,   //     MVN     R0, #$d
  0xe1a0f00e,   //     MOV     PC, LR
};

static unsigned int vul__put_user_8[] = {
  0xe4802004,   //     STR     R2, [R0], #$4
  0xe5803000,   //     STR     R3, [R0]
  0xe3a00000,   //     MOV     R0, #$0
  0xe1a0f00e,   //     MOV     PC, LR
};

static unsigned int vul__put_user_bad[] = {
  0xe3e0000d,   //     MVN     R0, #$d
  0xe1a0f00e,   //     MOV     PC, LR
};

static unsigned int fixed__get_user_1[] = {
  0xe92d400a,   //     STMPW   [SP], { R1, R3, LR }
  0xe3cd3d7f,   //     BIC     R3, SP, #$1fc0
  0xe3c3303f,   //     BIC     R3, R3, #$3f
  0xe5933008,   //     LDR     R3, [R3, #$8]
  0xe2433001,   //     SUB     R3, R3, #$1
  0xe1530000,   //     CMPS    R3, R0
  0x2a000007,   //     BCS     check_ok
  0xe1a01000,   //     MOV     R1, R0
  0xe59f0024,   //     LDR     R0, =format_str_address [$004c]
  0xe1a0200e,   //     MOV     R2, LR
  0xe59fe018,   //     LDR     LR, =printk_address [$0048]
  0xe12fff3e,   //     BLX     LR
  0xe3a02000,   //     MOV     R2, #$0
  0xe3e0000d,   //     MVN     R0, #$d
  0xe8bd800a,   //     LDMUW   [SP], { R1, R3, PC }
                // check_ok:
  0xe5d02000,   //     LDRB    R2, [R0]
  0xe3a00000,   //     MOV     R0, #$0
  0xe8bd800a,   //     LDMUW   [SP], { R1, R3, PC }
                // printk_address
                // format_str_address
};

static unsigned int fixed__get_user_2[] = {
  0xe92d400a,   //     STMPW   [SP], { R1, R3, LR }
  0xe3cd3d7f,   //     BIC     R3, SP, #$1fc0
  0xe3c3303f,   //     BIC     R3, R3, #$3f
  0xe5933008,   //     LDR     R3, [R3, #$8]
  0xe2433001,   //     SUB     R3, R3, #$1
  0xe2801001,   //     ADD     R1, R0, #$1
  0xe1530001,   //     CMPS    R3, R1
  0x2a000007,   //     BCS     check_ok
  0xe1a01000,   //     MOV     R1, R0
  0xe59f002c,   //     LDR     R0, =format_str_address [$0058]
  0xe1a0200e,   //     MOV     R2, LR
  0xe59fe020,   //     LDR     LR, =printk_address [$0054]
  0xe12fff3e,   //     BLX     LR
  0xe3a02000,   //     MOV     R2, #$0
  0xe3e0000d,   //     MVN     R0, #$d
  0xe8bd800a,   //     LDMUW   [SP], { R1, R3, PC }
                // check_ok:
  0xe4d02001,   //     LDRB    R2, [R0], #$1
  0xe5d03000,   //     LDRB    R3, [R0]
  0xe1822403,   //     ORR     R2, R2, R3 ,LSL #8
  0xe3a00000,   //     MOV     R0, #$0
  0xe8bd800a,   //     LDMUW   [SP], { R1, R3, PC }
                // printk_address
                // format_str_address
};

static unsigned int fixed__get_user_4[] = {
  0xe92d400a,   //     STMPW   [SP], { R1, R3, LR }
  0xe3cd3d7f,   //     BIC     R3, SP, #$1fc0
  0xe3c3303f,   //     BIC     R3, R3, #$3f
  0xe5933008,   //     LDR     R3, [R3, #$8]
  0xe2433001,   //     SUB     R3, R3, #$1
  0xe2801003,   //     ADD     R1, R0, #$3
  0xe1530001,   //     CMPS    R3, R1
  0x2a000007,   //     BCS     check_ok
  0xe1a01000,   //     MOV     R1, R0
  0xe59f0024,   //     LDR     R0, =format_str_address [$0050]
  0xe1a0200e,   //     MOV     R2, LR
  0xe59fe018,   //     LDR     LR, =printk_address [$004c]
  0xe12fff3e,   //     BLX     LR
  0xe3a02000,   //     MOV     R2, #$0
  0xe3e0000d,   //     MVN     R0, #$d
  0xe8bd800a,   //     LDMUW   [SP], { R1, R3, PC }
                // check_ok:
  0xe5902000,   //     LDR     R2, [R0]
  0xe3a00000,   //     MOV     R0, #$0
  0xe8bd800a,   //     LDMUW   [SP], { R1, R3, PC }
                // printk_address
                // format_str_address
};

static unsigned int fixed__put_user_1[] = {
  0xe92d400e,   //     STMPW   [SP], { R1-R3, LR }
  0xe3cd3d7f,   //     BIC     R3, SP, #$1fc0
  0xe3c3303f,   //     BIC     R3, R3, #$3f
  0xe5933008,   //     LDR     R3, [R3, #$8]
  0xe2433001,   //     SUB     R3, R3, #$1
  0xe1530000,   //     CMPS    R3, R0
  0x2a000008,   //     BCS     check_ok
  0xe1a01000,   //     MOV     R1, R0
  0xe3a000ff,   //     MOV     R0, #$ff
  0xe0002002,   //     AND     R2, R0, R2
  0xe59f0020,   //     LDR     R0, =format_str_address [$0050]
  0xe1a0300e,   //     MOV     R3, LR
  0xe59fe014,   //     LDR     LR, =printk_address [$004c]
  0xe12fff3e,   //     BLX     LR
  0xe3e0000d,   //     MVN     R0, #$d
  0xe8bd800e,   //     LDMUW   [SP], { R1-R3, PC }
                // check_ok:
  0xe5c02000,   //     STRB    R2, [R0]
  0xe3a00000,   //     MOV     R0, #$0
  0xe8bd800e,   //     LDMUW   [SP], { R1-R3, PC }
                // printk_address
                // format_str_address
};

static unsigned int fixed__put_user_2[] = {
  0xe92d400e,   //     STMPW   [SP], { R1-R3, LR }
  0xe3cd3d7f,   //     BIC     R3, SP, #$1fc0
  0xe3c3303f,   //     BIC     R3, R3, #$3f
  0xe5933008,   //     LDR     R3, [R3, #$8]
  0xe2433001,   //     SUB     R3, R3, #$1
  0xe2801001,   //     ADD     R1, R0, #$1
  0xe1530001,   //     CMPS    R3, R1
  0x2a000007,   //     BCS     check_ok
  0xe1a01000,   //     MOV     R1, R0
  0xe59f002c,   //     LDR     R0, =format_str_address [$0058]
  0xe6ff2072,   //     UXTH    R2, R2
  0xe1a0300e,   //     MOV     R3, LR
  0xe59fe01c,   //     LDR     LR, =printk_address [$0054]
  0xe12fff3e,   //     BLX     LR
  0xe3e0000d,   //     MVN     R0, #$d
  0xe8bd800e,   //     LDMUW   [SP], { R1-R3, PC }
                // check_ok:
  0xe1a03422,   //     MOV     R3, R2 ,LSR #8
  0xe4c02001,   //     STRB    R2, [R0], #$1
  0xe5c03000,   //     STRB    R3, [R0]
  0xe3a00000,   //     MOV     R0, #$0
  0xe8bd800e,   //     LDMUW   [SP], { R1-R3, PC }
                // printk_address
                // format_str_address
};

static unsigned int fixed__put_user_4[] = {
  0xe92d400e,   //     STMPW   [SP], { R1-R3, LR }
  0xe3cd3d7f,   //     BIC     R3, SP, #$1fc0
  0xe3c3303f,   //     BIC     R3, R3, #$3f
  0xe5933008,   //     LDR     R3, [R3, #$8]
  0xe2433001,   //     SUB     R3, R3, #$1
  0xe2801003,   //     ADD     R1, R0, #$3
  0xe1530001,   //     CMPS    R3, R1
  0x2a000006,   //     BCS     check_ok
  0xe1a01000,   //     MOV     R1, R0
  0xe59f0020,   //     LDR     R0, =format_str_address [$004c]
  0xe1a0300e,   //     MOV     R3, LR
  0xe59fe014,   //     LDR     LR, =printk_address [$0048]
  0xe12fff3e,   //     BLX     LR
  0xe3e0000d,   //     MVN     R0, #$d
  0xe8bd800e,   //     LDMUW   [SP], { R1-R3, PC }
                // check_ok:
  0xe5802000,   //     STR     R2, [R0]
  0xe3a00000,   //     MOV     R0, #$0
  0xe8bd800e,   //     LDMUW   [SP], { R1-R3, PC }
                // printk_address
                // format_str_address
};

static unsigned int fixed__put_user_8[] = {
  0xe92d401e,   //     STMPW   [SP], { R1-R4, LR }
  0xe3cd4d7f,   //     BIC     R4, SP, #$1fc0
  0xe3c4403f,   //     BIC     R4, R4, #$3f
  0xe5944008,   //     LDR     R4, [R4, #$8]
  0xe2444001,   //     SUB     R4, R4, #$1
  0xe2801007,   //     ADD     R1, R0, #$7
  0xe1540001,   //     CMPS    R4, R1
  0x2a000006,   //     BCS     check_ok
  0xe1a01000,   //     MOV     R1, R0
  0xe59f0024,   //     LDR     R0, =format_str_address [$0050]
  0xe1a0400e,   //     MOV     R4, LR
  0xe59fe018,   //     LDR     LR, =printk_address [$004c]
  0xe12fff3e,   //     BLX     LR
  0xe3e0000d,   //     MVN     R0, #$d
  0xe8bd801e,   //     LDMUW   [SP], { R1-R4, PC }
                // check_ok:
  0xe4802004,   //     STR     R2, [R0], #$4
  0xe5803000,   //     STR     R3, [R0]
  0xe3a00000,   //     MOV     R0, #$0
  0xe8bd801e,   //     LDMUW   [SP], { R1-R4, PC }
                // printk_address
                // format_str_address
};

static const char *get_format_str = "<3>__get_user_%d(): addr = %%p (from 0x%%08x)\n";
static const char *put_format_str = "<3>__put_user_%d(): addr = %%p, value = 0x%%08x (from 0x%%08x)\n";
static const char *put_format_str8 = "<3>__put_user_%d(): addr = %%p, value = 0x%%08x 0x%%08x  (from 0x%%08x)\n";

#define get_format_str1         get_format_str
#define get_format_str2         get_format_str
#define get_format_str4         get_format_str
#define put_format_str1         put_format_str
#define put_format_str2         put_format_str
#define put_format_str4         put_format_str

static kallsyms *kallsyms_info;

static unsigned int printk_address;
static unsigned int vmalloc_exec_address;
static unsigned int ptmx_fsync_address;

static void *exec_mem;

static unsigned int *__get_user_1_address;
static unsigned int *__get_user_2_address;
static unsigned int *__get_user_4_address;
static unsigned int *__get_user_bad_address;
static unsigned int *__put_user_1_address;
static unsigned int *__put_user_2_address;
static unsigned int *__put_user_4_address;
static unsigned int *__put_user_8_address;
static unsigned int *__put_user_bad_address;

static bool
kallsyms_init(void)
{
  if (!kallsyms_info) {
    kallsyms_info = kallsyms_in_memory_init((void *)BACKDOOR_MMAP_ADDRESS, BACKDOOR_MMAP_SIZE);
    if (!kallsyms_info) {
      return false;
    }
  }

  return true;
}

static void *
lookup_symbol_name(const char *name)
{
  if (!kallsyms_init()) {
    return NULL;
  }

  return (void *)kallsyms_in_memory_lookup_name(kallsyms_info, name);
}

static const char *
lookup_symbol_address(void *address)
{
  if (!kallsyms_init()) {
    return NULL;
  }

  return kallsyms_in_memory_lookup_address(kallsyms_info, (unsigned long)address);
}

#define LOOKUP_SYMBOL(type,num) \
  (__ ##type## _user_ ##num## _address = lookup_symbol_name("__" #type "_user_" #num))

static bool
setup_variables(void)
{
  unsigned int ptmx_fops_address;

  ptmx_fops_address = (unsigned int)get_ptmx_fops_address();
  if (!ptmx_fops_address) {
    ptmx_fops_address = (unsigned int)lookup_symbol_name("ptmx_fops");
  }

  if (!ptmx_fops_address) {
    return false;
  }

  ptmx_fsync_address = ptmx_fops_address + 0x38;

  printk_address = (unsigned int)lookup_symbol_name("printk");
  vmalloc_exec_address = (unsigned int)lookup_symbol_name("vmalloc_exec");

  if (!printk_address || !vmalloc_exec_address) {
    return false;
  }

  if (!LOOKUP_SYMBOL(get, 1)
   || !LOOKUP_SYMBOL(get, 2)
   || !LOOKUP_SYMBOL(get, 4)
   || !LOOKUP_SYMBOL(get, bad)
   || !LOOKUP_SYMBOL(put, 1)
   || !LOOKUP_SYMBOL(put, 2)
   || !LOOKUP_SYMBOL(put, 4)
   || !LOOKUP_SYMBOL(put, 8)
   || !LOOKUP_SYMBOL(put, bad)) {
    return false;
  }

  return true;
}

static bool
do_check_code(const unsigned int *actual, const unsigned int *expected, int len)
{
  const unsigned int *p = backdoor_convert_to_mmaped_address((void *)actual);
  int i;

  for (i = 0; i < len; i++) {
    if (p[i] != expected[i]) {
      return false;
    }
  }

  return true;
}

#define DO_CHECK(type,num) \
  do_check_code(__ ##type## _user_ ##num## _address, vul__ ##type## _user_ ##num, ARRAY_SIZE(vul__ ##type## _user_ ##num))

static bool
check_code(void)
{
  if (!DO_CHECK(get, 2)
   || !DO_CHECK(get, bad)
   || !DO_CHECK(put, 8)
   || !DO_CHECK(get, bad))
     return false;

  return true;
}

#define POS_PRINTK_PTR(code_size)       (code_size)
#define POS_STR_PTR(code_size)          (code_size + 4)
#define POS_STR(code_size)              (code_size + 4 + 4)

#define BUILD_CODE(type,num) \
static void *final__ ##type## _user_ ##num; \
static void *generated__ ##type## _user_ ##num; \
static int generated__ ##type## _user_ ##num## _size; \
static int generated__ ##type## _user_ ##num## _strpos; \
 \
static bool \
build_fixed__ ##type## _user_ ##num(void) \
{ \
  char str[256]; \
  char *p; \
  int size; \
  int code_size; \
 \
  code_size = sizeof fixed__ ##type## _user_ ##num; \
  sprintf(str, type## _format_str ##num, num); \
  size = POS_STR(code_size) + strlen(str) + 1; \
  size = (size + 3) & ~3; \
 \
  p = malloc(size); \
  if (!p) { \
    return false; \
  } \
 \
  memcpy(p, fixed__ ##type## _user_ ##num, code_size); \
 \
  *(unsigned int *)(p + POS_PRINTK_PTR(code_size)) = printk_address; \
  *(unsigned int *)(p + POS_STR_PTR(code_size)) = 0xdeadbeef; \
  strcpy(p + POS_STR(code_size), str); \
 \
  generated__ ##type## _user_ ##num = p; \
  generated__ ##type## _user_ ##num## _size = size; \
  generated__ ##type## _user_ ##num## _strpos = POS_STR_PTR(code_size); \
 \
  return true; \
}

BUILD_CODE(get, 1)
BUILD_CODE(get, 2)
BUILD_CODE(get, 4)
BUILD_CODE(put, 1)
BUILD_CODE(put, 2)
BUILD_CODE(put, 4)
BUILD_CODE(put, 8)

#define ADJUST_FINAL(type,num) \
  final__ ##type## _user_ ##num = p; \
  memcpy(p, generated__ ##type## _user_ ##num, generated__ ##type## _user_ ##num## _size); \
  *(void **)(p + generated__ ##type## _user_ ##num ## _strpos) = p + generated__ ##type## _user_ ##num ## _strpos + 4; \
  p += generated__ ##type## _user_ ##num ## _size;

static int
allocate_exec_mem(void)
{
  void *(*vmalloc_exec)(unsigned long size) = (void *)vmalloc_exec_address;
  void *p;
  int size;

  size = generated__get_user_1_size
       + generated__get_user_2_size
       + generated__get_user_4_size
       + generated__put_user_1_size
       + generated__put_user_2_size
       + generated__put_user_4_size
       + generated__put_user_8_size;

  if (!vmalloc_exec) {
    return;
  }

  exec_mem = (void *)vmalloc_exec(size);
  if (!exec_mem) {
    return;
  }

  p = exec_mem;

  ADJUST_FINAL(get, 1)
  ADJUST_FINAL(get, 2)
  ADJUST_FINAL(get, 4)
  ADJUST_FINAL(put, 1)
  ADJUST_FINAL(put, 2)
  ADJUST_FINAL(put, 4)
  ADJUST_FINAL(put, 8)
}

static bool
install_fixed_handler(void *orig, const void *fixed, void *work)
{
  // xxxxxx64: 0xea000006     B       $xxxxxx84

  // xxxxxx84: 0xe51ff004     LDR     PC, =fixed [pc + #4]
  // xxxxxx88: fixed

  unsigned int branch_offset;
  unsigned int *p;

  branch_offset = ((work - orig - 8) / 4);
  branch_offset &= ~0xff000000;

  p = backdoor_convert_to_mmaped_address(work);

  p[0] = 0xe51ff004;
  p[1] = (unsigned int)fixed;

  p = backdoor_convert_to_mmaped_address(orig);

  p[0] = 0xea000000 | branch_offset;

  p[1] = (unsigned int)fixed;
  p[0] = 0xe51ff004;

  return true;
}

#define INSTALL_FIXED_HANDLER(type,num,work) \
  if (!install_fixed_handler(__ ##type## _user_ ##num## _address, \
                             final__ ##type## _user_ ##num, work)) { \
    printf("Failed installing fixed __" #type "_user_" #num "()\n"); \
    return false; \
  }

static bool
fix_vulnerability(void)
{
  unsigned int *p;
  int fd;

  if (!build_fixed__get_user_1()
   || !build_fixed__get_user_2()
   || !build_fixed__get_user_4()
   || !build_fixed__put_user_1()
   || !build_fixed__put_user_2()
   || !build_fixed__put_user_4()
   || !build_fixed__put_user_8()) {
    return false;
  }

  p = backdoor_convert_to_mmaped_address((void *)ptmx_fsync_address);
  if (*p) {
    printf("Warning: ptmx_fsync is already used.\n");
    //return false;
  }

  *p = (unsigned int)&allocate_exec_mem;

  fd = open(PTMX_DEVICE, O_WRONLY);
  fsync(fd);
  close(fd);

  *p = 0;

  p = exec_mem;
  if (p == NULL) {
    printf("vmalloc_exec(): failed\n");
    return false;
  }

  INSTALL_FIXED_HANDLER(get, 1, __get_user_bad_address)
  INSTALL_FIXED_HANDLER(get, 2, __get_user_bad_address)
  INSTALL_FIXED_HANDLER(get, 4, __get_user_bad_address)
  INSTALL_FIXED_HANDLER(put, 1, __get_user_bad_address)
  INSTALL_FIXED_HANDLER(put, 2, __get_user_bad_address)
  INSTALL_FIXED_HANDLER(put, 4, __get_user_bad_address)
  INSTALL_FIXED_HANDLER(put, 8, __get_user_bad_address)

  return true;
}

int
main(int argc, char **argv)
{
  if (!backdoor_open_mmap()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));
    printf("Run 'install_backdoor' first\n");

    exit(EXIT_FAILURE);
  }

  if (!setup_variables()) {
    print_reason_device_not_supported();
    goto exit_failure;
  }

  if (!check_code()) {
    printf("Check code failed\n");
    goto exit_failure;
  }

  if (!fix_vulnerability()) {
    printf("Fix vulnerability failed\n");
    goto exit_failure;
  }

  backdoor_close_mmap();

  printf("Fixed CVE-2013-6282 vulnerability\n");
  exit(EXIT_SUCCESS);

exit_failure:
  backdoor_close_mmap();
  exit(EXIT_FAILURE);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
