// QunarNewDevice — 去哪儿旅行 一键新机 Tweak
// 目标: com.qunar.iphoneclient8 / QunariPhone_Cook_CM
// 依赖: ElleKit (Dopamine)

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import "profile.h"
#import "bypass.h"
#import "spoof.h"
#import "clean.h"
#import "tlog.h"
#import "net_capture.h"

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

// ── NSURLSession 代理注入（proxy 文件存在时生效）────────────────
%hook NSURLSessionConfiguration
- (NSDictionary *)connectionProxyDictionary {
    NSString *host = captureProxyHost();
    if (!host.length) return %orig;
    NSMutableDictionary *d = (%orig ? [%orig mutableCopy] : [NSMutableDictionary dictionary]);
    d[@"HTTPEnable"]  = @1; d[@"HTTPProxy"]  = host; d[@"HTTPPort"]  = @8080;
    d[@"HTTPSEnable"] = @1; d[@"HTTPSProxy"] = host; d[@"HTTPSPort"] = @8080;
    return [d copy];
}
%end

// ── WKWebView 初始化 hook — 注入指纹伪造脚本 ────────────────────
%hook WKWebView
- (instancetype)initWithFrame:(CGRect)frame configuration:(WKWebViewConfiguration *)config {
    tlog(@"wk_init_enter", nil);
    injectCaptureScript(config);
    tlog(@"wk_init_done", nil);
    return %orig;
}
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

// ── 按钮点击诊断 ─────────────────────────────────────────────────
@interface QSMSCodeLoginVC : NSObject
- (NSString *)qPhoneStr;
- (void)sendSMSCode:(id)param;
- (void)setQPhoneStr:(NSString *)phone;
@end

@interface QnrSendVCodeParam : NSObject
@end

@interface HYRiskyRequestVC : UIViewController
@end

static NSString *gCachedPhone = nil;

%hook QSMSCodeLoginVC
- (void)getSmsCodeClick {
    tlog(@"btn_click", @{@"c":@"QSMSCodeLoginVC",@"m":@"getSmsCodeClick"});
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        unsigned int mc = 0;
        Method *methods = class_copyMethodList([self class], &mc);
        NSMutableArray *names = [NSMutableArray array];
        for (unsigned int i = 0; i < mc; i++) {
            [names addObject:NSStringFromSelector(method_getName(methods[i]))];
        }
        free(methods);
        [names sortUsingSelector:@selector(compare:)];
        for (NSString *n in names) tlog(@"vc_method", @{@"m": n});
    });
    %orig;
}
- (void)setQPhoneStr:(NSString *)phone {
    if (phone.length) {
        gCachedPhone = [phone copy];
        tlog(@"set_phone", @{@"phone": phone});
    }
    %orig;
}
- (void)fetchSmsCode:(id)param {
    tlog(@"fetch_sms", @{@"param": [param description] ?: @"nil", @"cached": gCachedPhone ?: @"nil"});
    %orig;
}
- (void)sendSMSCode:(id)param {
    tlog(@"send_sms", @{@"param": [param description] ?: @"nil"});
    if (!param && gCachedPhone.length) {
        tlog(@"send_voice_as_sms", @{@"phone": gCachedPhone});
        %orig(gCachedPhone);
        return;
    }
    %orig;
}
%end

%hook QnrSendVCodeParam
- (void)setVcodeType:(id)type {
    tlog(@"vcode_type", @{@"v": [type description] ?: @"nil", @"cls": NSStringFromClass([type class]) ?: @"nil"});
    id sms = type;
    if ([type isKindOfClass:[NSString class]]) {
        if ([@[@"voice",@"VOICE",@"voice_call",@"2",@"3"] containsObject:type]) sms = @"1";
    } else if ([type isKindOfClass:[NSNumber class]]) {
        NSInteger n = [(NSNumber *)type integerValue];
        if (n == 2 || n == 3) sms = @(1);
    }
    if (sms != type) tlog(@"vcode_sms", @{@"was": [type description], @"now": [sms description]});
    %orig(sms);
}
%end

%hook QComVerifyLoginView
- (void)getVerifyCodeBtnClick {
    tlog(@"btn_click", @{@"c":@"QComVerifyLoginView",@"m":@"getVerifyCodeBtnClick"});
    %orig;
}
%end

// ── UILabel setText 诊断"频繁/安全"弹窗（仅记录，不阻断）─────
%hook UILabel
- (void)setText:(NSString *)text {
    if (text && ([text containsString:@"频繁"] || [text containsString:@"安全"] || [text containsString:@"异常"]))
        tlog(@"label_freq", @{@"t": text});
    %orig;
}
%end

// ── UIAlertController 捕获系统弹窗 ──────────────────────────────
%hook UIAlertController
- (void)viewDidLoad {
    %orig;
    NSString *t = self.title ?: @"";
    NSString *m = self.message ?: @"";
    if ([t containsString:@"频繁"] || [m containsString:@"频繁"] ||
        [t containsString:@"安全"] || [m containsString:@"安全"]) {
        tlog(@"alert_freq", @{@"t": t, @"m": m, @"stk": [[NSThread callStackSymbols] componentsJoinedByString:@"|"]});
    }
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

// ── 越狱检测诊断 probe（只记录不修改返回值）──────────────────────
%group GJailbreakProbe
%hook AppInfo
+ (BOOL)isJailBreak    { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"AppInfo",@"s":@"isJailBreak",@"r":@(r)}); return r; }
+ (BOOL)isJailBreakByEnv  { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"AppInfo",@"s":@"isJailBreakByEnv",@"r":@(r)}); return r; }
+ (BOOL)isJailBreakByStat { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"AppInfo",@"s":@"isJailBreakByStat",@"r":@(r)}); return r; }
%end
%hook NQPUtility
+ (BOOL)isJailBreak    { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"NQPUtility",@"s":@"isJailBreak",@"r":@(r)}); return r; }
+ (BOOL)isJailBreakByEnv  { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"NQPUtility",@"s":@"isJailBreakByEnv",@"r":@(r)}); return r; }
+ (BOOL)isJailBreakByStat { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"NQPUtility",@"s":@"isJailBreakByStat",@"r":@(r)}); return r; }
%end
%hook QPUtility
+ (BOOL)isJailBreak    { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"QPUtility",@"s":@"isJailBreak",@"r":@(r)}); return r; }
+ (BOOL)isJailBreakByEnv  { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"QPUtility",@"s":@"isJailBreakByEnv",@"r":@(r)}); return r; }
+ (BOOL)isJailBreakByStat { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"QPUtility",@"s":@"isJailBreakByStat",@"r":@(r)}); return r; }
%end
%hook CTDevice
+ (BOOL)isJailBreak { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"CTDevice",@"s":@"isJailBreak",@"r":@(r)}); return r; }
%end
%hook GTCDeviceUtils
- (BOOL)isJailbreak { tlog(@"gts_bypass", @{@"c":@"GTCDeviceUtils",@"m":@"isJailbreak->NO"}); return NO; }
%end
%hook GTSDeviceUtils
- (BOOL)isJailbreak { tlog(@"gts_bypass", @{@"c":@"GTSDeviceUtils",@"m":@"isJailbreak->NO"}); return NO; }
%end
%hook BMapDeviceInfo
+ (BOOL)isJailBreak { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"BMapDeviceInfo",@"s":@"isJailBreak",@"r":@(r)}); return r; }
%end
%hook QDeviceProfileInfo
+ (BOOL)isJailBreak { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"QDeviceProfileInfo",@"s":@"isJailBreak",@"r":@(r)}); return r; }
%end
%hook MidelOBJ
+ (BOOL)isJailbreak { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"MidelOBJ",@"s":@"isJailbreak",@"r":@(r)}); return r; }
%end
%hook CTPayFoundationUtil
+ (BOOL)isJailBreak { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"CTPayFoundationUtil",@"s":@"isJailBreak",@"r":@(r)}); return r; }
%end
%hook QTPUtils
+ (BOOL)isJailbreak { BOOL r = %orig; tlog(@"jb_probe", @{@"c":@"QTPUtils",@"s":@"isJailbreak",@"r":@(r)}); return r; }
%end
%hook HKEDeviceInfo
- (BOOL)isJailbroken   { tlog(@"gts_bypass", @{@"c":@"HKEDeviceInfo",@"m":@"isJailbroken->NO"});   return NO; }
- (BOOL)checkJailbroken { tlog(@"gts_bypass", @{@"c":@"HKEDeviceInfo",@"m":@"checkJailbroken->NO"}); return NO; }
%end
%end

// ── GTS 风险控制 bypass ─────────────────────────────────────────
typedef void (^QNCacheRiskCB)(NSArray *);

static void tryRespSuccess(id response, NSDictionary *data) {
    for (NSString *selStr in @[@"sendResponse:", @"resolve:", @"success:"]) {
        SEL s = NSSelectorFromString(selStr);
        if ([response respondsToSelector:s]) {
            ((void (*)(id, SEL, id))objc_msgSend)(response, s, data);
            tlog(@"rctl_resp_ok", @{@"sel": selStr});
            return;
        }
    }
    tlog(@"rctl_resp_unkn", @{@"cls": NSStringFromClass([response class])});
}

%group GRiskControl

%hook QRCTCacheRiskControl
- (void)cacheRiskControl:(id)params resultCallback:(QNCacheRiskCB)callback {
    tlog(@"rctl_bypass", @{@"m": @"cacheRiskControl:resultCallback:"});
    if (callback) callback(@[NSNull.null, @{@"code": @0, @"bizState": @0}]);
}
%end

%hook QRCTRiskControlInfo
- (void)getRiskControlInfo:(QNCacheRiskCB)callback {
    tlog(@"rctl_bypass", @{@"m": @"getRiskControlInfo:"});
    if (callback) callback(@[NSNull.null, @{@"code": @0, @"hasRisk": @NO}]);
}
%end

%hook HYRiskControlPlugin
- (void)riskControl:(id)params response:(id)response {
    tlog(@"rctl_bypass", @{@"m": @"riskControl:response:"});
    tryRespSuccess(response, @{@"code": @200, @"bizState": @0});
}
- (void)cacheRiskControl:(id)params response:(id)response {
    tlog(@"rctl_bypass", @{@"m": @"cacheRiskControl:response:"});
    tryRespSuccess(response, @{@"code": @200, @"bizState": @0});
}
%end

%hook QNPRiskInfoPlugin
- (void)getRiskInfo:(id)params response:(id)response {
    tlog(@"rctl_bypass", @{@"m": @"getRiskInfo:response:"});
    tryRespSuccess(response, @{@"code": @200});
}
%end

%hook HYRiskyRequestVC
- (void)viewDidLoad {
    tlog(@"risky_vc_load", nil);
    %orig;
}
%end

%end // GRiskControl

// ── 初始化 ────────────────────────────────────────────────────────
%ctor {
    @autoreleasepool {
        installSSLBypassAlways();
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        if ([bid isEqualToString:@"com.qunar.iphoneclient8"]) {
            NSString *marker = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/qn_ok"];
            [@"1" writeToFile:marker atomically:YES encoding:NSUTF8StringEncoding error:nil];
            [[NSFileManager defaultManager] removeItemAtPath:[NSTemporaryDirectory() stringByAppendingPathComponent:@"qunartweak_diag.log"] error:nil];
            tlog(@"tweak_loaded", nil);
            loadProfile();
            installBypassHooks();
            installSpoofHooks();
            initCleanHooks();
            %init;
            tlog(@"init_main_done", nil);
            dlopen("/System/Library/Frameworks/AdSupport.framework/AdSupport", RTLD_NOW);
            %init(GAdSupport);
            tlog(@"init_adsupport_done", nil);
            dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_NOW);
            %init(GCoreTelephony);
            tlog(@"init_telephony_done", nil);
            %init(GJailbreakProbe);
            tlog(@"init_jbprobe_done", nil);
            %init(GRiskControl);
            tlog(@"init_riskctl_done", nil);
        }
    }
}
