#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>
#import <sys/mount.h>
#import <sys/statvfs.h>
#import <dlfcn.h>
#import <substrate.h>
#import "profile.h"
#import "spoof.h"
#import "tlog.h"

static NSString *kcQueryKey(CFDictionaryRef q) {
    CFTypeRef svc = CFDictionaryGetValue(q, kSecAttrService);
    CFTypeRef acc = CFDictionaryGetValue(q, kSecAttrAccount);
    if (!svc || !acc) return nil;
    if (CFGetTypeID(svc) != CFStringGetTypeID() || CFGetTypeID(acc) != CFStringGetTypeID()) return nil;
    return [(__bridge NSString *)svc stringByAppendingFormat:@"/%@", (__bridge NSString *)acc];
}

static BOOL isQunarKey(NSString *key) {
    if (!key) return NO;
    if ([key containsString:@"qunar"] || [key containsString:@"iphoneclient"]) return YES;
    return NO;
}
static BOOL isGtsKey(NSString *key) {
    if (!key) return NO;
    return [key containsString:@"gxsdk"] || [key containsString:@"SDK_Service"];
}

static BOOL shouldBlockKey(NSString *key) {
    if (!key) return NO;
    @synchronized(gKeychainAllowedSet) {
        if ([gKeychainAllowedSet containsObject:key]) return NO;
    }
    return [gKeychainClearSet containsObject:key];
}

static int (*orig_statfs)(const char *, struct statfs *) = NULL;
static int hook_statfs(const char *path, struct statfs *buf) {
    int r = orig_statfs(path, buf);
    if (r != 0 || !gDiskTotal || !gDiskFree || buf->f_bsize == 0) return r;
    uint64_t bs = (uint64_t)buf->f_bsize;
    buf->f_blocks = (typeof(buf->f_blocks))([gDiskTotal unsignedLongLongValue] / bs);
    buf->f_bfree  = (typeof(buf->f_bfree)) ([gDiskFree  unsignedLongLongValue] / bs);
    buf->f_bavail = buf->f_bfree;
    return r;
}

static int (*orig_statvfs)(const char *, struct statvfs *) = NULL;
static int hook_statvfs(const char *path, struct statvfs *buf) {
    int r = orig_statvfs(path, buf);
    if (r != 0 || !gDiskTotal || !gDiskFree) return r;
    unsigned long fs = buf->f_frsize > 0 ? buf->f_frsize : buf->f_bsize;
    if (fs == 0) return r;
    buf->f_blocks = (typeof(buf->f_blocks))([gDiskTotal unsignedLongLongValue] / fs);
    buf->f_bfree  = (typeof(buf->f_bfree)) ([gDiskFree  unsignedLongLongValue] / fs);
    buf->f_bavail = buf->f_bfree;
    return r;
}

static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef) = NULL;
static CFDictionaryRef hook_CNCopyCurrentNetworkInfo(CFStringRef iface) {
    CFDictionaryRef orig = orig_CNCopyCurrentNetworkInfo(iface);
    if (!gWifiMAC || !orig) return orig;
    NSMutableDictionary *d = [(__bridge NSDictionary *)orig mutableCopy];
    CFRelease(orig);
    d[@"BSSID"] = gWifiMAC;
    return (CFDictionaryRef)CFBridgingRetain(d);
}

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static void logCFDataResult(CFTypeRef *result, NSString *key) {
    if (!result || !*result) return;
    NSData *data = nil;
    CFTypeRef rv = *result;
    if (CFGetTypeID(rv) == CFDataGetTypeID())
        data = (__bridge NSData *)rv;
    else if (CFGetTypeID(rv) == CFDictionaryGetTypeID()) {
        CFTypeRef v = CFDictionaryGetValue((CFDictionaryRef)rv, kSecValueData);
        if (v && CFGetTypeID(v) == CFDataGetTypeID()) data = (__bridge NSData *)v;
    }
    if (!data) return;
    NSMutableString *h = [NSMutableString string];
    for (NSUInteger i = 0; i < MIN(data.length, 32); i++)
        [h appendFormat:@"%02x", ((const uint8_t *)data.bytes)[i]];
    tlog(@"kc_read_val", @{@"key": key, @"hex": h, @"len": @(data.length)});
}

static OSStatus hook_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *result) {
    NSString *key = kcQueryKey(q);
    if (key && [key containsString:@"__gxsdk_reserved_key104__"]) {
        if (result) *result = NULL;
        tlog(@"kc_key104_not_found", @{@"key": key});
        return errSecItemNotFound;
    }
    // spoof GI/GX key1 → notFound，强迫 GTS 无缓存路径
    if (key && ([key containsString:@"_gikeychain_key1"] || [key containsString:@"_gxkeychain_key1"])) {
        tlog(@"kc_key1_spoofed", @{@"key": key});
        if (result) *result = NULL;
        return errSecItemNotFound;
    }
    if (shouldBlockKey(key)) {
        tlog(@"kc_blocked", @{@"key": key ?: @"nil"});
        if (result) *result = NULL;
        return errSecItemNotFound;
    }
    OSStatus r = orig_SecItemCopyMatching(q, result);
    if (r == errSecSuccess && key && isGtsKey(key))
        logCFDataResult(result, key);
    if (key && (isQunarKey(key) || isGtsKey(key)))
        tlog(@"kc_read", @{@"key": key, @"status": @(r)});
    return r;
}

static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);

static void logGtsValue(CFDictionaryRef attrs, NSString *key) {
    CFTypeRef v = CFDictionaryGetValue(attrs, kSecValueData);
    if (!v || CFGetTypeID(v) != CFDataGetTypeID()) return;
    NSData *d = (__bridge NSData *)v;
    NSUInteger len = MIN(d.length, 16);
    NSMutableString *hex = [NSMutableString string];
    for (NSUInteger i = 0; i < len; i++)
        [hex appendFormat:@"%02x", ((const uint8_t *)d.bytes)[i]];
    tlog(@"kc_gts_val", @{@"key": key, @"hex": hex, @"len": @(d.length)});
}

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus hook_SecItemAdd(CFDictionaryRef attrs, CFTypeRef *result) {
    NSString *key = kcQueryKey(attrs);
    OSStatus r = orig_SecItemAdd(attrs, result);
    if (r == errSecDuplicateItem && key && [gKeychainClearSet containsObject:key]) {
        orig_SecItemDelete(attrs);
        r = orig_SecItemAdd(attrs, result);
        if (r == errSecSuccess)
            tlog(@"kc_replaced", @{@"key": key});
    }
    if (r == errSecSuccess && key) {
        tlog(@"kc_written", @{@"key": key});
        if (isGtsKey(key)) logGtsValue(attrs, key);
        if (isQunarKey(key)) {
            @synchronized(gKeychainAllowedSet) { [gKeychainAllowedSet addObject:key]; }
            @synchronized(gKeychainClearSet)   { [gKeychainClearSet removeObject:key]; }
            saveKeychainAllowed();
        }
    }
    return r;
}

static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus hook_SecItemUpdate(CFDictionaryRef q, CFDictionaryRef attrs) {
    NSString *key = kcQueryKey(q);
    OSStatus r = orig_SecItemUpdate(q, attrs);
    if (r == errSecSuccess && key) {
        tlog(@"kc_updated", @{@"key": key});
        if (isQunarKey(key)) {
            @synchronized(gKeychainAllowedSet) { [gKeychainAllowedSet addObject:key]; }
            @synchronized(gKeychainClearSet)   { [gKeychainClearSet removeObject:key]; }
            saveKeychainAllowed();
        }
    }
    return r;
}

static id (*orig_advertisingIdentifier)(id, SEL);
static id hook_advertisingIdentifier(id self, SEL cmd) {
    if (gIDFA && gIDFA.length > 0) return [[NSUUID alloc] initWithUUIDString:gIDFA] ?: orig_advertisingIdentifier(self, cmd);
    return orig_advertisingIdentifier(self, cmd);
}

static BOOL (*orig_isAdTrackingEnabled)(id, SEL);
static BOOL hook_isAdTrackingEnabled(id self, SEL cmd) { return YES; }

static BOOL (*orig_isATTAuthorized)(id, SEL);
static BOOL hook_isATTAuthorized(id self, SEL cmd) { return YES; }

void installSpoofHooks(void) {
    MSHookFunction((void *)statfs,  (void *)hook_statfs,  (void **)&orig_statfs);
    MSHookFunction((void *)statvfs, (void *)hook_statvfs, (void **)&orig_statvfs);
    MSHookFunction((void *)SecItemCopyMatching, (void *)hook_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
    orig_SecItemDelete = SecItemDelete;
    MSHookFunction((void *)SecItemAdd,    (void *)hook_SecItemAdd,    (void **)&orig_SecItemAdd);
    MSHookFunction((void *)SecItemUpdate, (void *)hook_SecItemUpdate, (void **)&orig_SecItemUpdate);
    dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_NOW);
    void *fnCN = dlsym(RTLD_DEFAULT, "CNCopyCurrentNetworkInfo");
    if (fnCN) MSHookFunction(fnCN, (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
    Class ASClass = NSClassFromString(@"ASIdentifierManager");
    if (ASClass) {
        MSHookMessageEx(ASClass, @selector(advertisingIdentifier),
            (IMP)hook_advertisingIdentifier, (IMP *)&orig_advertisingIdentifier);
        MSHookMessageEx(ASClass, @selector(isAdvertisingTrackingEnabled),
            (IMP)hook_isAdTrackingEnabled, (IMP *)&orig_isAdTrackingEnabled);
        MSHookMessageEx(ASClass, @selector(isATTAuthorizationStatusAuthorized),
            (IMP)hook_isATTAuthorized, (IMP *)&orig_isATTAuthorized);
    }
    tlog(@"spoof_installed", nil);
}
