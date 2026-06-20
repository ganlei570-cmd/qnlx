TARGET  := iphone:clang:16.5:15.0
ARCHS   = arm64 arm64e
THEOS_PACKAGE_SCHEME = rootless
INSTALL_TARGET_PROCESSES = QunariPhone_Cook_CM

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = QunarNewDevice

QunarNewDevice_FILES        = Tweak.x bypass.mm net_capture.mm spoof.mm spoof_sofire.mm profile.mm clean.mm tlog.mm wk_logger.mm cloud_log.mm diag_sofire_m.x diag_sofire_files.x patch_sofire.x
QunarNewDevice_CFLAGS       = -fobjc-arc
QunarNewDevice_FRAMEWORKS   = UIKit Foundation Security CoreFoundation AdSupport CoreTelephony SystemConfiguration IOKit WebKit
QunarNewDevice_LIBRARIES    = substrate z

include $(THEOS)/makefiles/tweak.mk
# build trigger
