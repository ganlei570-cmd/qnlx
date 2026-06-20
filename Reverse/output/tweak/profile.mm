#import "profile.h"
#import "tlog.h"
#import "clean.h"
#import <Security/Security.h>

NSString *gIDFV = nil;
NSString *gIDFA = @"00000000-0000-0000-0000-000000000000";
NSString *gMachine    = nil;
NSString *gDeviceName = @"iPhone";
NSString *gCarrierName = @"中国移动";
NSString *gCarrierMCC  = @"460";
NSString *gCarrierMNC  = @"00";
NSString *gCarrierISO  = @"cn";
NSString *gSysVer    = nil;
NSNumber *gDiskTotal = nil;
NSNumber *gDiskFree  = nil;
NSString *gWifiMAC          = nil;
NSString *gBootSessionUUID  = nil;
NSString *gHardwareUUID     = nil;
NSString *gSerialNumber     = nil;
NSString *gSpoofGID         = nil;
NSString *gSpoofAID         = nil;
NSString *gSpoofINSTID      = nil;
NSMutableSet<NSString *> *gKeychainClearSet;
NSMutableSet<NSString *> *gKeychainAllowedSet;
BOOL gGtsRegistered = NO;

static NSString *qunarProfileDir(void) {
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    return [[dirs firstObject] stringByAppendingPathComponent:@"qunar_profiles"];
}

void saveKeychainAllowed(void) {
    @synchronized(gKeychainAllowedSet) {
        NSArray *arr = gKeychainAllowedSet.allObjects;
        NSData *d = [NSJSONSerialization dataWithJSONObject:arr options:0 error:nil];
        NSString *path = [qunarProfileDir() stringByAppendingPathComponent:@"kc_allowed.json"];
        [d writeToFile:path atomically:YES];
    }
}

static NSMutableSet<NSString *> *defaultKCSet(void) {
    return [NSMutableSet setWithArray:@[
        @"com.qunar.iphoneclient8.kClientIDKeychainKey/com.qunar.iphoneclient8",
        @"com.qunar.client.bc/client_bc",
        @"com.qunar.flight.bcd/flight_data",
        @"com.qunar.flight.bxcd/flight_data",
    ]];
}

static NSString *findActiveProfilePath(void) {
    return [qunarProfileDir() stringByAppendingPathComponent:@"active.json"];
}

static NSString * const kBadIDFV = @"A1B2C3D4-E5F6-7890-ABCD-EF1234567890";

static NSDictionary *diskProfile(void) {
    NSData *d = [NSData dataWithContentsOfFile:findActiveProfilePath()];
    if (!d) return nil;
    return [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
}

static NSString *randomSerial(void) {
    static const char *c = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
    NSMutableString *s = [NSMutableString stringWithCapacity:12];
    for (int i = 0; i < 12; i++) [s appendFormat:@"%c", c[arc4random_uniform(34)]];
    return [s copy];
}

static NSMutableSet<NSString *> *kcSetFromDict(NSDictionary *kc) {
    NSMutableSet *s = [NSMutableSet set];
    for (NSString *k in kc)
        if ([kc[k] isEqualToString:@"CLEAR"]) [s addObject:k];
    return s;
}

void loadProfile(void) {
    gKeychainClearSet   = defaultKCSet();
    gKeychainAllowedSet = [NSMutableSet set];

    NSData *ad = [NSData dataWithContentsOfFile:[qunarProfileDir() stringByAppendingPathComponent:@"kc_allowed.json"]];
    if (ad) {
        NSArray *arr = [NSJSONSerialization JSONObjectWithData:ad options:0 error:nil];
        if ([arr isKindOfClass:[NSArray class]])
            [gKeychainAllowedSet addObjectsFromArray:arr];
    }

    NSDictionary *p = diskProfile();
    if (!p) {
        gIDFV = [NSUUID UUID].UUIDString;
        NSString *dir = qunarProfileDir();
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        NSDictionary *minimal = @{@"idfv": gIDFV, @"idfa": @"00000000-0000-0000-0000-000000000000"};
        NSData *minData = [NSJSONSerialization dataWithJSONObject:minimal options:0 error:nil];
        [minData writeToFile:findActiveProfilePath() atomically:YES];
        tlog(@"profile_auto_generated", @{@"idfv": gIDFV});
        return;
    }

    if (p[@"idfv"])    gIDFV = p[@"idfv"];
    if (!gIDFV || [gIDFV isEqualToString:kBadIDFV]) {
        gIDFV = [NSUUID UUID].UUIDString;
        NSMutableDictionary *mp = [p mutableCopy];
        mp[@"idfv"] = gIDFV;
        NSData *ud = [NSJSONSerialization dataWithJSONObject:mp options:0 error:nil];
        [ud writeToFile:findActiveProfilePath() atomically:YES];
        tlog(@"idfv_auto_replaced", @{@"idfv": gIDFV});
    }
    if (p[@"idfa"])    gIDFA = p[@"idfa"];
    if (p[@"machine"]) gMachine = p[@"machine"];
    if (p[@"carrier_name"]) gCarrierName = p[@"carrier_name"];
    if (p[@"carrier_mcc"])  gCarrierMCC  = p[@"carrier_mcc"];
    if (p[@"carrier_mnc"])  gCarrierMNC  = p[@"carrier_mnc"];
    if (p[@"carrier_iso"])  gCarrierISO  = p[@"carrier_iso"];
    if (p[@"device_name"])  gDeviceName  = p[@"device_name"];
    if (p[@"sys_ver"])    gSysVer    = p[@"sys_ver"];
    if (p[@"disk_total"]) gDiskTotal = @([p[@"disk_total"] unsignedLongLongValue]);
    if (p[@"disk_free"])  gDiskFree  = @([p[@"disk_free"]  unsignedLongLongValue]);
    if (p[@"wifi_mac"])          gWifiMAC         = p[@"wifi_mac"];
    if (p[@"boot_session_uuid"]) gBootSessionUUID = p[@"boot_session_uuid"];
    if (p[@"hardware_uuid"])     gHardwareUUID    = p[@"hardware_uuid"];
    if (p[@"serial_number"]) {
        gSerialNumber = p[@"serial_number"];
    } else {
        gSerialNumber = randomSerial();
        NSMutableDictionary *mp = [p mutableCopy];
        mp[@"serial_number"] = gSerialNumber;
        NSData *ud = [NSJSONSerialization dataWithJSONObject:mp options:0 error:nil];
        [ud writeToFile:findActiveProfilePath() atomically:YES];
    }
    if (p[@"keychain"]) gKeychainClearSet = kcSetFromDict(p[@"keychain"]);
    if (p[@"app_gid"]) {
        gSpoofGID = p[@"app_gid"];
    } else {
        gSpoofGID = [NSUUID UUID].UUIDString;
        NSMutableDictionary *mp = [p mutableCopy];
        mp[@"app_gid"] = gSpoofGID;
        [[NSJSONSerialization dataWithJSONObject:mp options:0 error:nil]
            writeToFile:findActiveProfilePath() atomically:YES];
        tlog(@"app_gid_auto_gen", @{@"gid": [gSpoofGID substringToIndex:8]});
    }
    if (p[@"app_aid"]) {
        gSpoofAID = p[@"app_aid"];
    } else {
        gSpoofAID = [NSUUID UUID].UUIDString;
        NSMutableDictionary *mp = [p mutableCopy];
        mp[@"app_aid"] = gSpoofAID;
        [[NSJSONSerialization dataWithJSONObject:mp options:0 error:nil]
            writeToFile:findActiveProfilePath() atomically:YES];
        tlog(@"app_aid_auto_gen", @{@"aid": [gSpoofAID substringToIndex:8]});
    }
    if (p[@"app_instid"]) {
        gSpoofINSTID = p[@"app_instid"];
    } else {
        gSpoofINSTID = [NSUUID UUID].UUIDString;
        NSMutableDictionary *mp = [p mutableCopy];
        mp[@"app_instid"] = gSpoofINSTID;
        [[NSJSONSerialization dataWithJSONObject:mp options:0 error:nil]
            writeToFile:findActiveProfilePath() atomically:YES];
        tlog(@"app_instid_auto_gen", @{@"instid": [gSpoofINSTID substringToIndex:8]});
    }

    // 检测一键新机：IDFV 变了说明换机，自动清除登录态
    // 存 /tmp/ 避免被 companion app 清掉
    NSString *lastIDFVPath = @"/tmp/last_qunar_idfv.txt";
    NSString *lastIDFV = [NSString stringWithContentsOfFile:lastIDFVPath encoding:NSUTF8StringEncoding error:nil];
    if (lastIDFV && ![lastIDFV isEqualToString:gIDFV]) {
        tlog(@"new_machine_detected", @{@"old": lastIDFV ?: @"", @"new": gIDFV});
        clearQunarLoginState();
    }
    [gIDFV writeToFile:lastIDFVPath atomically:YES encoding:NSUTF8StringEncoding error:nil];

    // 检查 GTS SDK 是否已完成注册（key2 存在说明 CID 登记过，不再需要真实 IDFV）
    NSDictionary *gtsQ = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"GI__gikeychain_appkey1_SDK_Service",
        (__bridge id)kSecAttrAccount: @"_gikeychain_key2",
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
        (__bridge id)kSecReturnAttributes: @YES,
    };
    CFTypeRef gtsResult = NULL;
    OSStatus gtsStatus = SecItemCopyMatching((__bridge CFDictionaryRef)gtsQ, &gtsResult);
    gGtsRegistered = (gtsStatus == errSecSuccess);
    if (gtsResult) CFRelease(gtsResult);

    tlog(@"profile_ok", @{@"idfv_prefix": [gIDFV substringToIndex:MIN(8u, gIDFV.length)], @"gts_reg": @(gGtsRegistered)});
}
