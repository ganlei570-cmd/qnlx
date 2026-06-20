// patch_sofire.x — 在 doBlockingSessionTasks 返回后将 _tmpNumberValueu[@6] 从 63 patch 到 0
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import "tlog.h"

%hook SSMPRtDynamicSessiono

- (void)doBlockingSessionTasks {
    %orig;
    @try {
        Ivar ivar = class_getInstanceVariable(object_getClass(self), "_tmpNumberValueu");
        if (!ivar) {
            tlog(@"sf_patch", @{@"err": @"ivar_not_found"});
            return;
        }
        NSDictionary *orig = object_getIvar(self, ivar);
        id k6raw = orig[@6];
        int k6 = k6raw ? [k6raw intValue] : -1;
        if (k6 != 63) {
            tlog(@"sf_patch", @{@"skip": @"k6_not_63", @"k6": @(k6)});
            return;
        }
        NSMutableDictionary *patched = [NSMutableDictionary dictionaryWithDictionary:orig];
        patched[@6] = @0;
        object_setIvar(self, ivar, patched);
        tlog(@"sf_patch", @{@"ok": @1, @"k6_was": @63});
    } @catch (NSException *ex) {
        tlog(@"sf_patch_err", @{@"ex": ex.reason ?: @"?"});
    }
}

%end
