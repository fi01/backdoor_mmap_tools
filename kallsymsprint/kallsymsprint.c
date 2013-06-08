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
#include <sys/mman.h>
#include <ctype.h>
#include <fcntl.h>

#include "backdoor_mmap.h"

#define DBGPRINT(fmt...) fprintf(stderr, fmt)


typedef unsigned char uint8_t;
typedef unsigned short uint16_t;

static unsigned long  kallsyms_num_syms;
static unsigned long *kallsyms_addresses;
static uint8_t       *kallsyms_names;
static uint8_t       *kallsyms_token_table;
static uint16_t      *kallsyms_token_index;
static unsigned long *kallsyms_markers;

/*
 * Expand a compressed symbol data into the resulting uncompressed string,
 * given the offset to where the symbol is in the compressed stream.
 */
static unsigned int
kallsyms_expand_symbol(unsigned int off, char *result)
{
	int len, skipped_first = 0;
	const uint8_t *tptr, *data;

	/* Get the compressed symbol length from the first symbol byte. */
	data = &kallsyms_names[off];
	len = *data;
	data++;

	/*
	 * Update the offset to return the offset for the next symbol on
	 * the compressed stream.
	 */
	off += len + 1;

	/*
	 * For every byte on the compressed symbol data, copy the table
	 * entry for that byte.
	 */
	while (len) {
		tptr = &kallsyms_token_table[kallsyms_token_index[*data]];
		data++;
		len--;

		while (*tptr) {
			if (skipped_first) {
				*result = *tptr;
				result++;
			}
      else {
				skipped_first = 1;
      }

			tptr++;
		}
	}

	*result = '\0';

	/* Return to offset to the next symbol. */
	return off;
}

/* Lookup the address for this symbol. Returns 0 if not found. */
unsigned long
kallsyms_lookup_name(const char *name)
{
	char namebuf[1024];
	unsigned long i;
	unsigned int off;

	for (i = 0, off = 0; i < kallsyms_num_syms; i++) {
		off = kallsyms_expand_symbol(off, namebuf);
		if (strcmp(namebuf, name) == 0) {
			return kallsyms_addresses[i];
    }
	}
	return 0;
}

void
kallsyms_print_all()
{
	char namebuf[1024];
	unsigned long i;
	unsigned int off;

	for (i = 0, off = 0; i < kallsyms_num_syms; i++) {
		off = kallsyms_expand_symbol(off, namebuf);
    printf("%08x %s\n", (unsigned int)kallsyms_addresses[i], namebuf);
	}
	return;
}

static const unsigned long const pattern_kallsyms_addresses[] = {
    //0xc0008000, // __init_begin
    //0xc0008000, // _sinittext   // _sinittext is moved to 0xc0c00000
    0xc0008000,   // stext
    0xc0008000    // _text
};

static unsigned long *
search_pattern(unsigned long *base, unsigned long count, const unsigned long *const pattern, int patlen)
{
  unsigned long *addr = base;
  unsigned long i;
  for (i = 0; i < count; i++) {
    if(addr[i] != pattern[0]) {
      continue;
    }
    if (memcmp(&addr[i], pattern, patlen) == 0) {
      return &addr[i];
    }
  }
  return 0;
}

void
memdump(char *addr, int num, unsigned long offset)
{
  int i, j;
  int n = (num + 15) / 16;

  for (j = 0; j < n; j++) {
    printf("%08x : ", (unsigned int)addr + (unsigned int)offset);

    for (i = 0; i < 16; i++) {
      printf("%02x ", *addr++);
    }
    addr -= 16;
    for (i = 0; i < 16; i++) {
      if (*addr>=0x20 && *addr<0x80) {
        printf("%c", *addr);
      }
      else {
        printf(".");
      }
      addr++;
    }
    printf("\n");
  }
}

int
get_kallsyms_addresses(unsigned long *mem, unsigned long length, unsigned long offset)
{
  unsigned long *addr = mem;
  unsigned long *end = (unsigned long*)((unsigned long)mem + length);

  while (addr < end) {
    // get kallsyms_addresses pointer
    addr = search_pattern(addr, end - addr, pattern_kallsyms_addresses, sizeof(pattern_kallsyms_addresses));
    if (!addr) {
      return 0;
    }

    kallsyms_addresses = addr;
    DBGPRINT("[+]kallsyms_addresses=%08x\n", (unsigned int)kallsyms_addresses + (unsigned int)offset);

    // search end of kallsyms_addresses
    unsigned long n=0;
    while (addr[0] > 0xc0000000) {
      n++;
      addr++;
      if (addr >= end) {
        return 0;
      }
    }
    DBGPRINT("  count=%08x\n", (unsigned int)n);

    // skip there is filled by 0x0
    while (addr[0] == 0x00000000) {
      addr++;
      if (addr >= end) {
        return 0;
      }
    }

    kallsyms_num_syms = addr[0];
    addr++;
    if (addr >= end) {
      return 0;
    }
    DBGPRINT("[+]kallsyms_num_syms=%08x\n", (unsigned int)kallsyms_num_syms);

    // check kallsyms_num_syms
    if (kallsyms_num_syms != n) {
      continue;
    }

    // skip there is filled by 0x0
    while (addr[0] == 0x00000000) {
      addr++;
      if (addr >= end) {
        return 0;
      }
    }

    kallsyms_names = (uint8_t*)addr;
    DBGPRINT("[+]kallsyms_names=%08x\n", (unsigned int)kallsyms_names + (unsigned int)offset);

    // search end of kallsyms_names
    unsigned long i;
    unsigned int off;
    for (i = 0, off = 0; i < kallsyms_num_syms; i++) {
      int len = kallsyms_names[off];
      off += len + 1;
      if (&kallsyms_names[off] >= (uint8_t*)end) {
        return 0;
      }
    }

    // adjust
    addr = (unsigned long*)((((unsigned long)&kallsyms_names[off]-1)|0x3)+1);
    if (addr >= end) {
      return 0;
    }

    // skip there is filled by 0x0
    while (addr[0] == 0x00000000) {
      addr++;
      if (addr >= end) {
        return 0;
      }
    }
    // but kallsyms_markers shoud be start 0x00000000
    addr--;

    kallsyms_markers = addr;
    DBGPRINT("[+]kallsyms_markers=%08x\n", (unsigned int)kallsyms_markers + (unsigned int)offset);

    // end of kallsyms_markers
    addr = &kallsyms_markers[((kallsyms_num_syms-1)>>8)+1];
    if (addr >= end) {
      return 0;
    }

    // skip there is filled by 0x0
    while (addr[0] == 0x00000000) {
      addr++;
      if (addr >= end) {
        return 0;
      }
    }

    kallsyms_token_table = (uint8_t*)addr;
    DBGPRINT("[+]kallsyms_token_table=%08x\n", (unsigned int)kallsyms_token_table + (unsigned int)offset);

    // search end of kallsyms_token_table
    i = 0;
    while (kallsyms_token_table[i] != 0x00 || kallsyms_token_table[i+1] != 0x00) {
      i++;
      if (&kallsyms_token_table[i-1] >= (uint8_t*)end) {
        return 0;
      }
    }

    // skip there is filled by 0x0
    while (kallsyms_token_table[i] == 0x00) {
      i++;
      if (&kallsyms_token_table[i-1] >= (uint8_t*)end) {
        return 0;
      }
    }

    // but kallsyms_markers shoud be start 0x0000
    kallsyms_token_index = (uint16_t*)&kallsyms_token_table[i-2];
    DBGPRINT("[+]kallsyms_token_index=%08x\n", (unsigned int)kallsyms_token_index + (unsigned int)offset);

    return 1;
  }
  return 0;
}

int get_kallsyms(unsigned long *mem, size_t len)
{
  unsigned long mmap_offset = 0xc0008000 - (unsigned long)mem;
  DBGPRINT("[+]mmap\n");
  DBGPRINT("  mem=%08x length=%08x offset=%08x\n", (unsigned int)mem, (unsigned int)len, (unsigned int)mmap_offset);

  int ret = get_kallsyms_addresses(mem, len, mmap_offset);
  if (!ret) {
    fprintf(stderr, "kallsyms_addresses search failed\n");
    return false;
  }

  kallsyms_print_all();
  DBGPRINT("[+]kallsyms_lookup_name\n");

  return true;
}

static bool
do_kallsymsprint(void)
{
  bool ret;

  if (!backdoor_open_mmap()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));
    printf("Run 'install_backdoor' first\n");

    return false;
  }

  ret = get_kallsyms(backdoor_convert_to_mmaped_address((void *)0xc0008000), BACKDOOR_MMAP_SIZE);

  backdoor_close_mmap();
  return ret;
}

int
main(int argc, char **argv)
{
  if (!do_kallsymsprint()) {
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
