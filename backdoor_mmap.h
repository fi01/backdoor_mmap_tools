#include <stdbool.h>

#define BACKDOOR_MMAP_SIZE    0x0a000000
#define BACKDOOR_MMAP_ADDRESS 0x20000000

extern void *backdoor_convert_to_kernel_address(void *address);
extern void *backdoor_convert_to_mmaped_address(void *address);

extern bool backdoor_open_mmap(void);
extern bool backdoor_close_mmap(void);
