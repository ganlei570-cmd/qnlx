#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <WebKit/WebKit.h>
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

static void clearQunarDefaults(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *dict = [ud dictionaryRepresentation];
    NSArray *loginKeys = @[
        @"qunar_user", @"qunar_token", @"qunar_login",
        @"qunar_passport", @"qunar_account", @"qunar_session",
        @"kUserLoggedIn", @"kCurrentUserName", @"kCurrentUserId",
        @"QULoginStatus", @"QUCurrentUser", @"passport_login",
    ];
    int count = 0;
    for (NSString *key in dict.allKeys) {
        NSString *lower = key.lowercaseString;
        BOOL isLogin = NO;
        for (NSString *k in loginKeys)
            if ([lower containsString:k.lowercaseString]) { isLogin = YES; break; }
        if (isLogin) { [ud removeObjectForKey:key]; count++; }
    }
    [ud synchronize];
    tlog(@"defaults_cleared", @{@"count": @(count)});
}

static void clearQunarLoginKeychain(void) {
    NSArray *classes = @[(__bridge id)kSecClassGenericPassword,
                         (__bridge id)kSecClassInternetPassword];
    int count = 0;
    for (id cls in classes) {
        NSDictionary *q = @{
            (__bridge id)kSecClass:           cls,
            (__bridge id)kSecAttrAccessGroup: @"H682X2BYS8.com.qunar.iphoneclient8",
        };
        OSStatus r = SecItemDelete((__bridge CFDictionaryRef)q);
        if (r == errSecSuccess) count++;
    }
    tlog(@"kc_login_cleared", @{@"count": @(count)});
}

static void handleClearSafari(CFNotificationCenterRef c, void *o,
                               CFStringRef n, const void *obj, CFDictionaryRef i) {
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *p in safariTargets())
        [fm removeItemAtPath:p error:nil];
    clearQunarCookies();
    clearQunarDefaults();
    clearQunarLoginKeychain();
    tlog(@"login_cleared", nil);
}

void clearQunarLoginState(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *container = NSHomeDirectory();
    NSString *lib = [container stringByAppendingPathComponent:@"Library"];

    for (NSString *sub in @[@"WebKit", @"Cookies", @"Application Support"]) {
        NSString *path = [lib stringByAppendingPathComponent:sub];
        [fm removeItemAtPath:path error:nil];
    }

    NSString *prefsBase = @"/var/mobile/Library/Preferences";
    for (NSString *f in [fm contentsOfDirectoryAtPath:prefsBase error:nil]) {
        if ([f containsString:@"qunar"] || [f containsString:@"iphoneclient8"])
            [fm removeItemAtPath:[prefsBase stringByAppendingPathComponent:f] error:nil];
    }

    clearQunarLoginKeychain();
    clearQunarDefaults();
    tlog(@"login_cleared", nil);
}

static void handleClearLogin(CFNotificationCenterRef c, void *o,
                              CFStringRef n, const void *obj, CFDictionaryRef i) {
    clearQunarLoginState();
}

void initCleanHooks(void) {
    NSString *pendingPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/qunar_new_machine_pending"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:pendingPath]) {
        [[NSFileManager defaultManager] removeItemAtPath:pendingPath error:nil];
        tlog(@"new_machine_pending_detected", nil);
        clearQunarLoginState();
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
