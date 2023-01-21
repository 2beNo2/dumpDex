LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := dumpDex
LOCAL_SRC_FILES := main.cpp
LOCAL_LDLIBS := -lc -ldl -llog

include $(BUILD_EXECUTABLE)