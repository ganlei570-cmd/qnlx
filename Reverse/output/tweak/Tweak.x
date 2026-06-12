// QunarNewDevice — 去哪儿旅行 一键新机 Tweak
// 目标: com.qunar.iphoneclient8 / QunariPhone_Cook_CM
// 依赖: ElleKit (Dopamine)

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import <dlfcn.h>
#import "profile.h"
#import "bypass.h"
#import "spoof.h"
#import "clean.h"
#import "tlog.h"

// ── WKWebView SSL bypass ─────────────────────────────────────────
static const char kWKNavSpyKey = 0;

@interface QunarWKNavSpy : NSObject <WKNavigationDelegate>
@property (nonatomic, weak) id<WKNavigationDelegate> real;
@end

@implementation QunarWKNavSpy
- (BOOL)respondsToSelector:(SEL)sel {
    if (sel == @selector(webView:didReceiveAuthenticationChallenge:completionHandler:)) return YES;
    if (sel == @selector(webView:decidePolicyForNavigationAction:decisionHandler:)) return YES;
    return [self.real respondsToSelector:sel];
}
- (id)forwardingTargetForSelector:(SEL)sel {
    return self.real;
}
- (void)webView:(WKWebView *)wv
decidePolicyForNavigationAction:(WKNavigationAction *)action
decisionHandler:(void(^)(WKNavigationActionPolicy))handler {
    tlog(@"wk_nav", @{@"url": action.request.URL.absoluteString ?: @""});
    if ([self.real respondsToSelector:_cmd])
        [self.real webView:wv decidePolicyForNavigationAction:action decisionHandler:handler];
    else
        handler(WKNavigationActionPolicyAllow);
}
- (void)webView:(WKWebView *)wv
    didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)ch
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))cb {
    if ([ch.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        cb(NSURLSessionAuthChallengeUseCredential,
           [NSURLCredential credentialForTrust:ch.protectionSpace.serverTrust]);
        tlog(@"wk_ssl_bypass", @{@"host": ch.protectionSpace.host ?: @""});
    } else if ([self.real respondsToSelector:_cmd]) {
        [self.real webView:wv didReceiveAuthenticationChallenge:ch completionHandler:cb];
    } else {
        cb(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}
@end

// ── WKWebView delegate hook ──────────────────────────────────────
%hook WKWebView
- (void)setNavigationDelegate:(id<WKNavigationDelegate>)delegate {
    if (!delegate) { %orig(nil); return; }
    QunarWKNavSpy *spy = [QunarWKNavSpy new];
    spy.real = delegate;
    objc_setAssociatedObject(self, &kWKNavSpyKey, spy, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    %orig(spy);
}
%end

// ── NSURLConnection SSL bypass ───────────────────────────────────
%hook NSURLConnection
- (void)connection:(NSURLConnection *)conn
    willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)ch {
    if ([ch.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        [ch.sender useCredential:[NSURLCredential credentialForTrust:ch.protectionSpace.serverTrust]
              forAuthenticationChallenge:ch];
        tlog(@"conn_ssl_bypass", @{@"host": ch.protectionSpace.host ?: @""});
    } else {
        [ch.sender performDefaultHandlingForAuthenticationChallenge:ch];
    }
}
- (BOOL)connection:(NSURLConnection *)conn canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)sp {
    return [sp.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] ? YES : %orig;
}
%end

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
