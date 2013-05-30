LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  detect_device.c \
  cred.c \
  kallsyms.c \
  main.c \
  ptmx.c \
  backdoor_mmap.c

LOCAL_MODULE := run_root_shell
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES += libcutils libc

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  detect_device.c \
  kallsyms.c \
  reset_security_ops.c \
  ptmx.c \
  backdoor_mmap.c

LOCAL_MODULE := reset_security_ops
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES += libcutils libc

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  detect_device.c \
  kallsyms.c \
  disable_ccsecurity.c \
  backdoor_mmap.c

LOCAL_MODULE := disable_ccsecurity
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES += libcutils libc

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  detect_device.c \
  install_backdoor.c \
  backdoor_mmap.c \
  kallsyms.c \
  perf_swevent.c \
  ptmx.c \
  mm.c

LOCAL_MODULE := install_backdoor
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES := libdiagexploit
LOCAL_STATIC_LIBRARIES += libcutils libc

include $(BUILD_EXECUTABLE)

include $(call all-makefiles-under,$(LOCAL_PATH))
