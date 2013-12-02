#define SECURITY_NAME_MAX       10
#define SECURITY_OPS_OFFSET     ((SECURITY_NAME_MAX + 3) / 4)

extern void *get_fjsec_security_ops();
