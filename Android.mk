LOCAL_PATH:=$(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	radiotap.c \
	packetspammer.c

LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../external/libpcap

LOCAL_STATIC_LIBRARIES += libpcap
LOCAL_MODULE := packetspammer

include $(BUILD_EXECUTABLE)
