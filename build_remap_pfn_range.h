#ifndef __BUILD_REMAP_PFN_RANGE_H__
#define __BUILD_REMAP_PFN_RANGE_H__

#define MAX_REMAP_PFN_RANGE_SIZE        1024

typedef struct _custom_remap_pfn_range_param_t {
  unsigned long remap_pfn_range_address;
  unsigned long remap_pfn_range_end_op;
  unsigned long security_remap_pfn_range_address;

  unsigned long *custom_remap_pfn_range_func;
  unsigned long custom_remap_pfn_range_size;
} custom_remap_pfn_range_param_t;

bool build_custom_remap_pfn_range_func(custom_remap_pfn_range_param_t *param);

#endif /* __BUILD_REMAP_PFN_RANGE_H__ */
