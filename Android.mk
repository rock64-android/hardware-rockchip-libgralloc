##############################################################################
#  
#    Copyright (c) 2005 - 2011 by Vivante Corp.  All rights reserved.
#  
#    The material in this file is confidential and contains trade secrets
#    of Vivante Corporation. This is proprietary information owned by
#    Vivante Corporation. No part of this work may be disclosed, 
#    reproduced, copied, transmitted, or used in any way for any purpose, 
#    without the express written permission of Vivante Corporation.
#  
##############################################################################
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_PREBUILT_LIBS := gralloc.$(TARGET_BOARD_HARDWARE).so
LOCAL_MODULE_TAGS    := optional
LOCAL_MODULE_PATH    := $(TARGET_OUT_SHARED_LIBRARIES)/hw
include $(BUILD_MULTI_PREBUILT)

