#include <stdbool.h>
#include <stdio.h>
#include "build_remap_pfn_range.h"

#define ARRAY_SIZE(x)   (sizeof (x) / sizeof (*(x)))

#define LONG_BRANCH_OP  0xebfffffe
#define MOV_R0_ZERO_OP  0xe3a00000

static unsigned long long_branch_addr[32];
static num_long_branch;

static unsigned long long_branch[] = {
  0xe92d4010,   // STMPW   [SP], { R4, LR }
  0xe59f4004,   // LDR     R4, =$deadbeef [pc + $c]
  0xe12fff34,   // BX      R4
  0xe8bd8010,   // LDMUW   [SP], { R4, PC }
                // DW      $deadbeef
};

bool
build_custom_remap_pfn_range_func(custom_remap_pfn_range_param_t *param)
{
  unsigned long *func = param->custom_remap_pfn_range_func;
  unsigned long size;
  int i;

  num_long_branch = 0;
  size = 0;

  for (i = 0; i < MAX_REMAP_PFN_RANGE_SIZE / 4; i++) {
    unsigned long op;

    op = func[i];

    if (op == param->remap_pfn_range_end_op) {
      size = i + 1;
      break;
    }

    //printf("%08x: %08x", param->remap_pfn_range_address + i * 4, op);

    if ((op & 0xff000000) == 0xeb000000) {
      unsigned long branch_addr;
      unsigned long off;

      off = (op & 0x00ffffff);
      if (off & 0x00800000) {
        off |= 0xff000000;
      }

      branch_addr = (param->remap_pfn_range_address + i * 4) + off * 4 + 8;

      //printf("\tBL\t$%08x", branch_addr);

      if (branch_addr == param->security_remap_pfn_range_address) {
	op = MOV_R0_ZERO_OP;
      }
      else {
	off = (branch_addr - ((unsigned long)func + i * 4) - 8) / 4;
	if (off & 0xff000000) {
	  off &= 0x007fffff;
	  off |= 0x00800000;
	}

	op = 0xeb000000 | off;

	off = (op & 0x00ffffff);
	if (off & 0x00800000) {
	  off |= 0xff000000;
	}

	if (branch_addr != ((unsigned long)func + i * 4) + off * 4 + 8) {
	  //printf("\naddess %p is out of range!\n", branch_addr);

	  long_branch_addr[num_long_branch++] = branch_addr;
	  op = LONG_BRANCH_OP;
	}
      }

      func[i] = op;
    }

    if ((op & 0xff000000) == 0xc0000000) {
      //printf("\tDW\t$%08x", op);
    }

    //printf("\n");
  }

  if (size == 0) {
    return false;
  }

  num_long_branch = 0;
  for (i = 0; i < size; i++) {
    if (func[i] == LONG_BRANCH_OP) {
      unsigned long branch_addr;
      unsigned long off;
      int j;

      branch_addr = (unsigned long)func + size * 4;

      off = (branch_addr - ((unsigned long)func + i * 4) - 8) / 4;
      if (off & 0xff000000) {
        off &= 0x007fffff;
        off |= 0x00800000;
      }

      func[i] = 0xeb000000 | off;

      if (size + ARRAY_SIZE(long_branch) + 1 >= MAX_REMAP_PFN_RANGE_SIZE / 4) {
        return false;
      }

      for (j = 0; j < ARRAY_SIZE(long_branch); j++) {
        func[size++] = long_branch[j];
      }

      func[size++] = long_branch_addr[num_long_branch++];
    }
  }

  param->custom_remap_pfn_range_size = size * 4;

  return true;
}
