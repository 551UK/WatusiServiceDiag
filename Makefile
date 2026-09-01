export TARGET = iphone:clang:14.5:14.5
export ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = WatusiServiceDiag

WatusiServiceDiag_FILES = Tweak.x
WatusiServiceDiag_CFLAGS = -fobjc-arc -Wall -Wextra -I$(THEOS_PROJECT_DIR)
WatusiServiceDiag_FRAMEWORKS = Foundation
WatusiServiceDiag_LIBRARIES = proc

include $(THEOS_MAKE_PATH)/tweak.mk
