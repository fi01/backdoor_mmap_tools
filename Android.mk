LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  cred.c \
  kallsyms.c \
  main.c \
  ptmx.c \
  backdoor_mmap.c \
  mmap.c

LOCAL_MODULE := run_root_shell
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES += libdevice_database
LOCAL_STATIC_LIBRARIES += libcutils libc
LOCAL_LDFLAGS += -static

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  kallsyms.c \
  reset_security_ops.c \
  ptmx.c \
  backdoor_mmap.c

LOCAL_MODULE := reset_security_ops
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES += libdevice_database
LOCAL_STATIC_LIBRARIES += libcutils libc
LOCAL_LDFLAGS += -static

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  disable_ccsecurity.c \
  backdoor_mmap.c

LOCAL_MODULE := disable_ccsecurity
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES += libkallsyms
LOCAL_STATIC_LIBRARIES += libdevice_database
LOCAL_STATIC_LIBRARIES += libcutils libc
LOCAL_LDFLAGS += -static

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  fix_cve_2013_6282.c \
  kallsyms.c \
  ptmx.c \
  backdoor_mmap.c

LOCAL_MODULE := fix_cve_2013_6282
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES += libkallsyms
LOCAL_STATIC_LIBRARIES += libdevice_database
LOCAL_STATIC_LIBRARIES += libcutils libc
LOCAL_LDFLAGS += -static

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  install_backdoor.c \
  backdoor_mmap.c \
  kallsyms.c \
  ptmx.c \
  mm.c \
  mmap.c \
  build_remap_pfn_range.c

LOCAL_MODULE := install_backdoor
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES := libdiagexploit
LOCAL_STATIC_LIBRARIES += libperf_event_exploit
LOCAL_STATIC_LIBRARIES += libdevice_database
LOCAL_STATIC_LIBRARIES += libmsm_acdb_exploit
LOCAL_STATIC_LIBRARIES += libfj_hdcp_exploit
LOCAL_STATIC_LIBRARIES += libput_user_exploit
LOCAL_STATIC_LIBRARIES += libfb_mem_exploit
LOCAL_STATIC_LIBRARIES += libfutex_exploit
LOCAL_STATIC_LIBRARIES += libz_static
LOCAL_STATIC_LIBRARIES += libcutils libc
LOCAL_LDFLAGS += -static

TOP_SRCDIR := $(abspath $(LOCAL_PATH))
TARGET_C_INCLUDES += \
  $(TOP_SRCDIR)/device_database

include $(BUILD_EXECUTABLE)

include $(call all-makefiles-under,$(LOCAL_PATH))
