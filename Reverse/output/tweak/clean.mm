#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <WebKit/WebKit.h>
#import <UIKit/UIKit.h>
#import "clean.h"
#import "tlog.h"

static NSArray<NSString *> *safariTargets(void) {
    NSString *base = @"/var/mobile/Library/Safari";
    NSArray *names = @[
        @"History.db", @"History.db-shm", @"History.db-wal",
        @"BrowserState.db", @"BrowserState.db-shm", @"BrowserState.db-wal",
        @"SafariTabs.db", @"SafariTabs.db-shm", @"SafariTabs.db-wal",
        @"CloudTabs.db", @"CloudTabs.db-shm", @"CloudTabs.db-wal",
    ];
    NSMutableArray *paths = [NSMutableArray array];
    for (NSString *n in names)
        [paths addObject:[base stringByAppendingPathComponent:n]];
    return paths;
}

static void clearQunarCookies(void) {
    NSHTTPCookieStorage *jar = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray<NSHTTPCookie *> *all = [jar cookies];
    int count = 0;
    for (NSHTTPCookie *c in all) {
        if ([c.domain containsString:@"qunar"] || [c.domain containsString:@"qunarzz"]) {
            [jar deleteCookie:c];
            count++;
        }
    }
    tlog(@"cookies_cleared", @{@"count": @(count)});
}

static NSArray<NSString *> *udLoginKeys(void) {
    return @[@"qunar_user",@"qunar_token",@"qunar_login",@"qunar_passport",
             @"qunar_account",@"qunar_session",@"kUserLoggedIn",@"kCurrentUserName",
             @"kCurrentUserId",@"QULoginStatus",@"QUCurrentUser",@"passport_login"];
}

static void clearQunarDefaults(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *dict = [ud dictionaryRepresentation];
    int count = 0;
    for (NSString *key in dict.allKeys) {
        NSString *lower = key.lowercaseString;
        BOOL isLogin = NO;
        for (NSString *k in udLoginKeys())
            if ([lower containsString:k.lowercaseString]) { isLogin = YES; break; }
        if (isLogin) { [ud removeObjectForKey:key]; count++; }
    }
    [ud removeObjectForKey:@"kClientIDKey"];
    [ud synchronize];
    tlog(@"defaults_cleared", @{@"count": @(count)});
}

static void deleteKCItem(id cls, NSDictionary *item) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    d[(__bridge id)kSecClass]           = cls;
    d[(__bridge id)kSecAttrAccessGroup] = @"H682X2BYS8.com.qunar.iphoneclient8";
    NSString *svc = item[(__bridge id)kSecAttrService];
    NSString *acc = item[(__bridge id)kSecAttrAccount];
    if (svc) d[(__bridge id)kSecAttrService] = svc;
    if (acc) d[(__bridge id)kSecAttrAccount] = acc;
    SecItemDelete((__bridge CFDictionaryRef)d);
}

static void clearKeychainItems(BOOL includeGts) {
    NSArray *classes = @[(__bridge id)kSecClassGenericPassword,
                         (__bridge id)kSecClassInternetPassword];
    int count = 0;
    for (id cls in classes) {
        NSDictionary *q = @{
            (__bridge id)kSecClass:            cls,
            (__bridge id)kSecAttrAccessGroup:  @"H682X2BYS8.com.qunar.iphoneclient8",
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecMatchLimit:       (__bridge id)kSecMatchLimitAll,
        };
        tlog(@"clr_kc_before_query", @{@"cls": (NSString *)cls});
        CFTypeRef raw = NULL;
        OSStatus qs = SecItemCopyMatching((__bridge CFDictionaryRef)q, &raw);
        tlog(@"clr_kc_after_query", @{@"cls": (NSString *)cls, @"status": @(qs)});
        if (qs != errSecSuccess || !raw) continue;
        NSArray *items = (CFGetTypeID(raw) == CFArrayGetTypeID())
            ? (__bridge_transfer NSArray *)raw : @[(__bridge_transfer id)raw];
        tlog(@"clr_kc_items", @{@"cls": (NSString *)cls, @"n": @(items.count)});
        for (NSDictionary *item in items) {
            NSString *svc = item[(__bridge id)kSecAttrService];
            if (!includeGts && ([svc hasPrefix:@"GI_"] || [svc hasPrefix:@"GX_"])) continue;
            deleteKCItem(cls, item);
            count++;
        }
        tlog(@"clr_kc_deleted", @{@"cls": (NSString *)cls, @"n": @(count)});
    }
    tlog(@"kc_cleared", @{@"count": @(count), @"gts": @(includeGts)});
}


static void clearCacheDb(void) {
    NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/com.qunar.iphoneclient8"];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *s in @[@"/Cache.db", @"/Cache.db-shm", @"/Cache.db-wal"])
        [fm removeItemAtPath:[dir stringByAppendingString:s] error:nil];
    tlog(@"cache_db_cleared", nil);
}

void clearAccountOnly(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *lib = [NSHomeDirectory() stringByAppendingPathComponent:@"Library"];
    [fm removeItemAtPath:[lib stringByAppendingPathComponent:@"Cookies"] error:nil];
    dispatch_async(dispatch_get_main_queue(), ^{
        WKWebsiteDataStore *store = [WKWebsiteDataStore defaultDataStore];
        NSSet *types = [NSSet setWithObjects:
            WKWebsiteDataTypeLocalStorage,
            WKWebsiteDataTypeSessionStorage,
            WKWebsiteDataTypeIndexedDBDatabases,
            WKWebsiteDataTypeOfflineWebApplicationCache,
            WKWebsiteDataTypeDiskCache,
            WKWebsiteDataTypeMemoryCache, nil];
        [store removeDataOfTypes:types modifiedSince:[NSDate dateWithTimeIntervalSince1970:0]
              completionHandler:^{}];
    });
    clearQunarCookies();
    clearQunarDefaults();
    clearKeychainItems(NO);
    tlog(@"account_only_cleared", nil);
}

static void handleClearSafari(CFNotificationCenterRef c, void *o,
                               CFStringRef n, const void *obj, CFDictionaryRef i) {
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *p in safariTargets())
        [fm removeItemAtPath:p error:nil];
    clearAccountOnly();
}

void clearQunarLoginState(void) {
    tlog(@"clr_step", @{@"s": @"enter"});
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *lib = [NSHomeDirectory() stringByAppendingPathComponent:@"Library"];

    [fm removeItemAtPath:[lib stringByAppendingPathComponent:@"Cookies"] error:nil];
    dispatch_async(dispatch_get_main_queue(), ^{
        WKWebsiteDataStore *store = [WKWebsiteDataStore defaultDataStore];
        NSSet *types = [NSSet setWithObjects:
            WKWebsiteDataTypeLocalStorage,
            WKWebsiteDataTypeSessionStorage,
            WKWebsiteDataTypeIndexedDBDatabases,
            WKWebsiteDataTypeOfflineWebApplicationCache,
            WKWebsiteDataTypeDiskCache,
            WKWebsiteDataTypeMemoryCache, nil];
        [store removeDataOfTypes:types modifiedSince:[NSDate dateWithTimeIntervalSince1970:0]
              completionHandler:^{}];
    });
    tlog(@"clr_step", @{@"s": @"webkit_done"});

    NSString *prefsBase = @"/var/mobile/Library/Preferences";
    for (NSString *f in [fm contentsOfDirectoryAtPath:prefsBase error:nil]) {
        if ([f containsString:@"qunar"] || [f containsString:@"iphoneclient8"])
            [fm removeItemAtPath:[prefsBase stringByAppendingPathComponent:f] error:nil];
    }
    tlog(@"clr_step", @{@"s": @"prefs_done"});

    clearQunarCookies();
    tlog(@"clr_step", @{@"s": @"cookies_done"});

    clearQunarDefaults();
    tlog(@"clr_step", @{@"s": @"defaults_done"});

    clearKeychainItems(NO);
    tlog(@"clr_step", @{@"s": @"keychain_done"});

    clearCacheDb();
    tlog(@"login_cleared", nil);
}

static void handleClearLogin(CFNotificationCenterRef c, void *o,
                              CFStringRef n, const void *obj, CFDictionaryRef i) {
    clearAccountOnly();
}

static void clearGtsKeys(void) {
    NSArray *accs = @[
        @"__gxsdk_reserved_key7__",
        @"__gxsdk_reserved_key3__",
        @"__gxsdk_reserved_key44__",
        @"__gxsdk_reserved_key72__",
        @"__gxsdk_reserved_key104__",
    ];
    for (NSString *acc in accs) {
        NSDictionary *q = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                              (__bridge id)kSecAttrAccount: acc };
        OSStatus r = SecItemDelete((__bridge CFDictionaryRef)q);
        tlog(@"gts_key_del", @{@"acc": acc, @"r": @(r)});
    }
    NSString *gtsDbDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/gtRoot/GtkDB"];
    NSError *dbErr = nil;
    BOOL dbRemoved = [[NSFileManager defaultManager] removeItemAtPath:gtsDbDir error:&dbErr];
    tlog(@"gts_db_cleared", @{@"ok": @(dbRemoved), @"err": dbErr.localizedDescription ?: @"nil"});
}

void initCleanHooks(void) {
    NSString *pendingPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/qunar_new_machine_pending"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:pendingPath]) {
        [[NSFileManager defaultManager] removeItemAtPath:pendingPath error:nil];
        tlog(@"new_machine_pending_detected", nil);
        // 同步删 gtsdk.sqlite — 必须在 GTS SDK 读取它之前执行
        NSString *gtsDbDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/gtRoot/GtkDB"];
        NSError *dbErr = nil;
        BOOL dbRemoved = [[NSFileManager defaultManager] removeItemAtPath:gtsDbDir error:&dbErr];
        tlog(@"gts_db_sync_cleared", @{@"ok": @(dbRemoved), @"err": dbErr.localizedDescription ?: @"nil"});
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
            clearGtsKeys();
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            NSURL *url = [NSURL URLWithString:@"qunariphone://uc/logout"];
            [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:^(BOOL ok) {
                tlog(@"logout_url_triggered", @{@"ok": @(ok)});
            }];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                clearQunarLoginState();
            });
        });
    }
    CFNotificationCenterAddObserver(
        CFNotificationCenterGetDarwinNotifyCenter(),
        NULL,
        handleClearSafari,
        CFSTR("com.qunar.newmachine.clearSafari"),
        NULL,
        CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(
        CFNotificationCenterGetDarwinNotifyCenter(),
        NULL,
        handleClearLogin,
        CFSTR("com.qunar.newmachine.clearLogin"),
        NULL,
        CFNotificationSuspensionBehaviorDeliverImmediately);
}
