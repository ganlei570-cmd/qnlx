// QunarNewDevice — 去哪儿旅行 一键新机 Tweak
// 目标: com.qunar.iphoneclient8 / QunariPhone_Cook_CM
// 依赖: ElleKit (Dopamine)

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import "profile.h"
#import "bypass.h"
#import "spoof.h"
#import "clean.h"
#import "tlog.h"

// ── UIKit hooks ──────────────────────────────────────────────────
%hook UIDevice
- (NSUUID *)identifierForVendor { return [[NSUUID alloc] initWithUUIDString:gIDFV]; }
- (NSString *)name              { return gDeviceName ?: @"iPhone"; }
- (NSString *)systemVersion     { return gSysVer ?: %orig; }
%end

%hook NSFileManager
- (NSDictionary *)attributesOfFileSystemForPath:(NSString *)path error:(NSError **)error {
    NSDictionary *orig = %orig;
    if (!gDiskTotal || !gDiskFree || !orig) return orig;
    NSMutableDictionary *d = [orig mutableCopy];
    d[NSFileSystemSize]     = gDiskTotal;
    d[NSFileSystemFreeSize] = gDiskFree;
    return [d copy];
}
%end

// ── AdSupport hook ───────────────────────────────────────────────
%group GAdSupport
%hook ASIdentifierManager
- (NSUUID *)advertisingIdentifier {
    return [[NSUUID alloc] initWithUUIDString:gIDFA];
}
%end
%end

// ── CoreTelephony hook ───────────────────────────────────────────
%group GCoreTelephony
%hook CTCarrier
- (NSString *)carrierName        { return gCarrierName; }
- (NSString *)mobileCountryCode  { return gCarrierMCC; }
- (NSString *)mobileNetworkCode  { return gCarrierMNC; }
- (NSString *)isoCountryCode     { return gCarrierISO; }
%end
%end

// TODO: 去哪儿登录保护 — 需运行时 hook SecItemAdd/class-dump 定位 logout 类名
// 候选待确认: QUAccountManager / QunarAccountService / ...

// ── 初始化 ────────────────────────────────────────────────────────
%ctor {
    @autoreleasepool {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        if ([bid isEqualToString:@"com.qunar.iphoneclient8"]) {
            [@"1" writeToFile:@"/tmp/qunartweak_loaded" atomically:YES encoding:NSUTF8StringEncoding error:nil];
            tlog(@"tweak_loaded", nil);
            loadProfile();
            installBypassHooks();
            installSpoofHooks();
            initCleanHooks();
            %init;
            dlopen("/System/Library/Frameworks/AdSupport.framework/AdSupport", RTLD_NOW);
            %init(GAdSupport);
            dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_NOW);
            %init(GCoreTelephony);
        }
    }
}
