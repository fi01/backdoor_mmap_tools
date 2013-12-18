LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  ../kallsyms.c \
  unlock_sec_sc04e.c \
  ../ptmx.c \
  ../backdoor_mmap.c

LOCAL_MODULE := unlock_sec_sc04e
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES += .
LOCAL_STATIC_LIBRARIES += libdevice_database
LOCAL_STATIC_LIBRARIES += libcutils libc
LOCAL_LDFLAGS += -static

include $(BUILD_EXECUTABLE)
