#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <Security/SecureTransport.h>
#import <CFNetwork/CFNetwork.h>
#import <CommonCrypto/CommonCryptor.h>
#import <dlfcn.h>
#import <zlib.h>
#import <substrate.h>
#import "profile.h"
#import "tlog.h"
#import "net_capture.h"
#import "wk_logger.h"

static NSData *tryGunzip(const void *data, size_t len) {
    if (len < 10) return nil;
    const uint8_t *b = (const uint8_t *)data;
    if (b[0] != 0x1f || b[1] != 0x8b) return nil;
    z_stream strm = {0};
    strm.next_in  = (Bytef *)data;
    strm.avail_in = (uInt)len;
    if (inflateInit2(&strm, 15 + 16) != Z_OK) return nil;
    NSMutableData *out = [NSMutableData dataWithLength:len * 6 + 1024];
    strm.next_out  = (Bytef *)out.mutableBytes;
    strm.avail_out = (uInt)out.length;
    int ret = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);
    if (ret != Z_STREAM_END) return nil;
    out.length = strm.total_out;
    return out;
}

static BOOL isRelevant(NSString *s) {
    if (!s) return NO;
    return [s containsString:@"qunar"]     || [s containsString:@"risk"]       ||
           [s containsString:@"passport"]  || [s containsString:@"login"]      ||
           [s containsString:@"\"data\":false"] || [s containsString:@"\"result\":false"] ||
           [s containsString:@"verifycode"] || [s containsString:@"register"]  ||
           [s containsString:@"Params error"] ||
           [s containsString:@"hotel"]     || [s containsString:@"roomList"]   ||
           [s containsString:@"hotelList"] || [s containsString:@"errCode"]    ||
           [s containsString:@"hotelId"]   || [s containsString:@"price"]      ||
           [s containsString:@"风险"]      || [s containsString:@"异常"]        ||
           [s containsString:@"错误"]      || [s containsString:@"失败"]       ||
           [s containsString:@"getui"]     || [s containsString:@"gtcid"]      ||
           [s containsString:@"GTCID"]     || [s containsString:@"aesSecret"];
}

static OSStatus (*orig_SSLRead)(SSLContextRef, void *, size_t, size_t *);
static OSStatus hook_SSLRead(SSLContextRef ctx, void *data, size_t dataLen, size_t *processed) {
    OSStatus r = orig_SSLRead(ctx, data, dataLen, processed);
    if (r != 0 || !processed || *processed < 20) return r;
    @try {
        NSString *s = nil;
        NSData *gz = tryGunzip(data, *processed);
        if (gz) {
            s = [[NSString alloc] initWithData:gz encoding:NSUTF8StringEncoding];
        } else {
            s = [[NSString alloc] initWithBytes:data length:*processed encoding:NSUTF8StringEncoding];
        }
        if (isRelevant(s))
            tlog(@"ssl_resp", @{@"gz": @(gz != nil), @"s": s.length > 800 ? [s substringToIndex:800] : s});
    } @catch(id e) {}
    return r;
}

static OSStatus (*orig_SSLWrite)(SSLContextRef, const void *, size_t, size_t *);
static OSStatus hook_SSLWrite(SSLContextRef ctx, const void *data, size_t dataLen, size_t *processed) {
    @try {
        if (dataLen > 10) {
            NSString *s = [[NSString alloc] initWithBytes:data length:MIN(dataLen, 2000) encoding:NSUTF8StringEncoding];
            if (s && ([s containsString:@"qunar.com"] || [s containsString:@"passport"] ||
                      [s containsString:@"risk"] || [s containsString:@"phone"] ||
                      [s containsString:@"sms"] || [s containsString:@"verif"] ||
                      [s containsString:@"sendCode"] || [s containsString:@"register"]))
                tlog(@"ssl_req", @{@"s": s.length > 2000 ? [s substringToIndex:2000] : s});
        }
    } @catch(id e) {}
    return orig_SSLWrite(ctx, data, dataLen, processed);
}

static char kVcodeAccKey = 0;

@interface QunarNetSpy : NSObject
@property (nonatomic, strong) id real;
@end

@implementation QunarNetSpy

- (BOOL)respondsToSelector:(SEL)s {
    if (class_respondsToSelector([QunarNetSpy class], s)) return YES;
    return self.real && [self.real respondsToSelector:s];
}

- (id)forwardingTargetForSelector:(SEL)s {
    return self.real;
}

- (void)URLSession:(NSURLSession *)sess dataTask:(NSURLSessionDataTask *)t didReceiveData:(NSData *)d {
    @try {
        NSString *u = t.currentRequest.URL.absoluteString ?: @"";
        if ([u containsString:@"p_ucGetVcodeV2"]) {
            NSMutableData *acc = objc_getAssociatedObject(t, &kVcodeAccKey);
            if (!acc) {
                acc = [NSMutableData data];
                objc_setAssociatedObject(t, &kVcodeAccKey, acc, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            }
            [acc appendData:d];
        } else if (([u containsString:@"qunar.com"] || [u containsString:@"getui.com"] || [u containsString:@"getui.cn"]) && ![u containsString:@"slugger"]) {
            NSString *b = nil;
            NSData *gz = tryGunzip(d.bytes, d.length);
            if (gz) b = [[NSString alloc] initWithData:gz encoding:NSUTF8StringEncoding];
            if (!b) b = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (!b) b = @"[bin]";
            tlog(@"resp_data", @{
                @"u": u.length > 200 ? [u substringToIndex:200] : u,
                @"b": b.length > 500 ? [b substringToIndex:500] : b
            });
        }
    } @catch(id e) {}
    id r = self.real;
    if (r && [r respondsToSelector:_cmd])
        [r URLSession:sess dataTask:t didReceiveData:d];
}

- (void)URLSession:(NSURLSession *)sess dataTask:(NSURLSessionDataTask *)t
    didReceiveResponse:(NSURLResponse *)response
    completionHandler:(void (^)(NSURLSessionResponseDisposition))cb {
    @try {
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            NSString *u = t.currentRequest.URL.absoluteString ?: @"";
            if ([u containsString:@"apple.com"])
                tlog(@"apple_resp", @{
                    @"status": @([(NSHTTPURLResponse *)response statusCode]),
                    @"u": u.length > 120 ? [u substringToIndex:120] : u
                });
        }
    } @catch(id e) {}
    __block BOOL called = NO;
    void (^once)(NSURLSessionResponseDisposition) = ^(NSURLSessionResponseDisposition d) {
        if (!called) { called = YES; cb(d); }
    };
    id r = self.real;
    if (r && [r respondsToSelector:_cmd])
        [r URLSession:sess dataTask:t didReceiveResponse:response completionHandler:once];
    else
        once(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)sess task:(NSURLSessionTask *)t didCompleteWithError:(NSError *)e {
    @try {
        NSString *u = t.currentRequest.URL.absoluteString ?: @"";
        if ([u containsString:@"p_ucGetVcodeV2"]) {
            NSMutableData *acc = objc_getAssociatedObject(t, &kVcodeAccKey);
            NSString *str = acc ? ([[NSString alloc] initWithData:acc encoding:NSUTF8StringEncoding] ?: @"[bin]") : @"[no_data]";
            NSMutableString *hexStr = [NSMutableString string];
            const uint8_t *rawBytes = (const uint8_t *)acc.bytes;
            for (NSUInteger hi = 0; hi < MIN(acc.length, 128); hi++)
                [hexStr appendFormat:@"%02x", rawBytes[hi]];
            tlog(@"vcode_resp", @{
                @"len": @(acc.length),
                @"str": str.length > 600 ? [str substringToIndex:600] : str,
                @"err": e.localizedDescription ?: @"",
                @"hex": hexStr
            });
        } else if ([u containsString:@"apple.com"]) {
            tlog(@"apple_done", @{
                @"u": u.length > 120 ? [u substringToIndex:120] : u,
                @"e": e.localizedDescription ?: @"",
                @"code": @(e.code)
            });
        } else if (([u containsString:@"qunar.com"] || [u containsString:@"getui.com"] || [u containsString:@"getui.cn"]) && ![u containsString:@"slugger"]) {
            tlog(@"resp_done", @{
                @"u": u.length > 120 ? [u substringToIndex:120] : u,
                @"e": e.localizedDescription ?: @""
            });
        }
    } @catch(id e2) {}
    id r = self.real;
    if (r && [r respondsToSelector:_cmd])
        [r URLSession:sess task:t didCompleteWithError:e];
}

- (void)URLSession:(NSURLSession *)sess
    didReceiveChallenge:(NSURLAuthenticationChallenge *)ch
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))cb {
    if ([ch.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        cb(NSURLSessionAuthChallengeUseCredential,
           [NSURLCredential credentialForTrust:ch.protectionSpace.serverTrust]);
    } else {
        id r = self.real;
        if (r && [r respondsToSelector:_cmd]) [r URLSession:sess didReceiveChallenge:ch completionHandler:cb];
        else cb(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

- (void)URLSession:(NSURLSession *)sess task:(NSURLSessionTask *)t
    didReceiveChallenge:(NSURLAuthenticationChallenge *)ch
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))cb {
    if ([ch.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        cb(NSURLSessionAuthChallengeUseCredential,
           [NSURLCredential credentialForTrust:ch.protectionSpace.serverTrust]);
    } else {
        id r = self.real;
        if (r && [r respondsToSelector:_cmd]) [r URLSession:sess task:t didReceiveChallenge:ch completionHandler:cb];
        else cb(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

@end

static id (*orig_newSess)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *);
static id hook_newSess(id s, SEL c, NSURLSessionConfiguration *cfg, id d, NSOperationQueue *q) {
    // skip background sessions (identifier != nil) — avoids deadlock in CKCrashReporter
    if (d && cfg && !cfg.identifier) {
        QunarNetSpy *spy = [QunarNetSpy new];
        spy.real = d;
        d = spy;
    }
    return orig_newSess(s, c, cfg, d, q);
}

// 全量捕获：completion handler 方式的请求（无 delegate）
static id (*orig_dataTaskReq)(id, SEL, NSURLRequest *, void *);
static id hook_dataTaskReq(id self, SEL cmd, NSURLRequest *req, void *handler) {

    @try {
        NSString *u = req.URL.absoluteString ?: @"";
        if ([u containsString:@"sofire.baidu.com"] && [u containsString:@"/s/"]) {
            typedef void (^SofireHandler)(NSData *, NSURLResponse *, NSError *);
            SofireHandler orig = (__bridge SofireHandler)handler;
            SofireHandler wrapped = [^(NSData *d, NSURLResponse *r, NSError *e) {
                @try {
                    NSString *body = d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
                    tlog(@"sofire_s", @{@"url": u.length > 200 ? [u substringToIndex:200] : u,
                                        @"status": @([(NSHTTPURLResponse *)r statusCode]),
                                        @"body": body ?: @"(binary)",
                                        @"len": @(d.length)});
                } @catch(id e2) {}
                if (orig) orig(d, r, e);
            } copy];
            return orig_dataTaskReq(self, cmd, req, (__bridge void *)wrapped);
        }
        if ([u containsString:@"qunar"]) {
            tlog(@"req_all", @{@"u": u.length > 200 ? [u substringToIndex:200] : u,
                               @"m": req.HTTPMethod ?: @"GET"});
            if ([u containsString:@"qunar"]) {
                NSData *body = req.HTTPBody;
                if (body.length > 0) {
                    NSString *bs = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
                    tlog(@"req_body", @{
                        @"u": u.length > 100 ? [u substringToIndex:100] : u,
                        @"b": (bs ?: @"[binary]").length > 1500 ? [(bs ?: @"[binary]") substringToIndex:1500] : (bs ?: @"[binary]")
                    });
                }
            }
        }
    } @catch(id e) {}
    return orig_dataTaskReq(self, cmd, req, handler);
}

static id (*orig_dataTaskURL)(id, SEL, NSURL *, void *);
static id hook_dataTaskURL(id self, SEL cmd, NSURL *url, void *handler) {
    @try {
        NSString *u = url.absoluteString ?: @"";
        if ([u containsString:@"sofire.baidu.com"] && [u containsString:@"/s/"]) {
            typedef void (^SofireHandler)(NSData *, NSURLResponse *, NSError *);
            SofireHandler orig = (__bridge SofireHandler)handler;
            SofireHandler wrapped = [^(NSData *d, NSURLResponse *r, NSError *e) {
                @try {
                    NSString *body = d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
                    tlog(@"sofire_s", @{@"url": u.length > 200 ? [u substringToIndex:200] : u,
                                        @"status": @([(NSHTTPURLResponse *)r statusCode]),
                                        @"body": body ?: @"(binary)",
                                        @"len": @(d.length)});
                } @catch(id e2) {}
                if (orig) orig(d, r, e);
            } copy];
            return orig_dataTaskURL(self, cmd, url, (__bridge void *)wrapped);
        }
    } @catch(id e) {}
    return orig_dataTaskURL(self, cmd, url, handler);
}

// delegate-based dataTask（h_hlist 走这条路）
static id (*orig_dataTaskReqDel)(id, SEL, NSURLRequest *);
static id hook_dataTaskReqDel(id self, SEL cmd, NSURLRequest *req) {
    @try {
        NSString *u = req.URL.absoluteString ?: @"";
        BOOL isTarget = [u containsString:@"qunar"] || [u containsString:@"getui"];
        if (isTarget) {
            NSData *body = req.HTTPBody;
            if ([u containsString:@"p_ucGetVcodeV2"]) {
                NSString *bs = body ? ([[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding] ?: @"[bin]") : @"[no_body]";
                NSMutableString *hexReq = [NSMutableString string];
                const uint8_t *rb = (const uint8_t *)body.bytes;
                for (NSUInteger hi = 0; hi < MIN(body.length, 256); hi++)
                    [hexReq appendFormat:@"%02x", rb[hi]];
                tlog(@"vcode_req", @{
                    @"u": u.length > 200 ? [u substringToIndex:200] : u,
                    @"len": @(body.length),
                    @"hex": hexReq,
                    @"str": bs.length > 800 ? [bs substringToIndex:800] : bs
                });
                NSArray *stk = [NSThread callStackSymbols];
                NSMutableString *sf = [NSMutableString string];
                for (NSUInteger fi = 1; fi < MIN((NSUInteger)20, stk.count); fi++)
                    [sf appendFormat:@"\n%@", stk[fi]];
                tlog(@"vcode_stack", @{@"s": sf});
            } else {
                NSString *bs = body ? ([[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding] ?: @"[bin]") : @"[no_body]";
                NSString *tag = [u containsString:@"getui"] ? @"req_getui" : @"req_del";
                tlog(tag, @{
                    @"u": u.length > 200 ? [u substringToIndex:200] : u,
                    @"m": req.HTTPMethod ?: @"GET",
                    @"b": bs.length > 1500 ? [bs substringToIndex:1500] : bs
                });
            }
        }
    } @catch(id e) {}
    return orig_dataTaskReqDel(self, cmd, req);
}

// ── WKWebView JS 注入：浏览器指纹伪造 + 请求日志 ────────────────
void injectCaptureScript(WKWebViewConfiguration *configuration) {
    if (!configuration) return;
    registerWKLogger(configuration);
    // 从 hardware_uuid 派生种子，换 profile 就换指纹
    NSString *uuid = gHardwareUUID ?: @"DEADBEEF-0000-0000-0000-000000000000";
    NSString *hex = [[[uuid stringByReplacingOccurrencesOfString:@"-" withString:@""]
                      substringToIndex:8] uppercaseString];
    unsigned int seed = 0;
    [[NSScanner scannerWithString:hex] scanHexInt:&seed];
    if (seed == 0) seed = 0xDEADC0DE;
    tlog(@"wk_inject", @{@"seed": [NSString stringWithFormat:@"%08X", seed]});
    NSString *js = [NSString stringWithFormat:
        @"(function(){"
        "if(window.__qnSpoof)return;window.__qnSpoof=true;"
        "var sd=%u>>>0;"
        "function nr(){sd=((sd*1664525>>>0)+1013904223)>>>0;return(sd>>>1)&3;}"
        // ── Canvas 2D 指纹 ──
        "var _gi=CanvasRenderingContext2D.prototype.getImageData;"
        "CanvasRenderingContext2D.prototype.getImageData=function(){"
        "var d=_gi.apply(this,arguments);d.data[0]^=nr();d.data[1]^=nr();return d;};"
        "var _td=HTMLCanvasElement.prototype.toDataURL;"
        "HTMLCanvasElement.prototype.toDataURL=function(){"
        "try{var c=HTMLCanvasElement.prototype.getContext.call(this,'2d');"
        "if(c){var p=_gi.call(c,0,0,1,1);p.data[0]^=nr();p.data[1]^=nr();c.putImageData(p,0,0);}"
        "}catch(e){}return _td.apply(this,arguments);};"
        "if(HTMLCanvasElement.prototype.toBlob){"
        "var _tb=HTMLCanvasElement.prototype.toBlob;"
        "HTMLCanvasElement.prototype.toBlob=function(cb,t,q){"
        "var self=this;"
        "try{var c=HTMLCanvasElement.prototype.getContext.call(this,'2d');"
        "if(c){var p=_gi.call(c,0,0,1,1);p.data[0]^=nr();p.data[1]^=nr();c.putImageData(p,0,0);}}"
        "catch(e){}return _tb.call(self,cb,t,q);};}"
        // ── WebGL 1 + 2 指纹 ──
        "var fr='Apple A'+((sd%%3)+16)+' GPU';"
        "function _swgl(gl){if(!gl)return gl;"
        "var _p=gl.getParameter.bind(gl);"
        "gl.getParameter=function(p){"
        "if(p===0x1F01||p===0x9246)return fr;"
        "if(p===0x1F00||p===0x9245)return 'Apple Inc.';"
        "return _p(p);};"
        "var _rp=gl.readPixels.bind(gl);"
        "gl.readPixels=function(x,y,w,h,fmt,type,pixels){"
        "_rp(x,y,w,h,fmt,type,pixels);"
        "if(pixels&&pixels.length>0){pixels[0]^=nr();if(pixels.length>1)pixels[1]^=nr();}};"
        "return gl;}"
        "var _gc=HTMLCanvasElement.prototype.getContext;"
        "HTMLCanvasElement.prototype.getContext=function(t){"
        "var c=_gc.apply(this,arguments);"
        "if(c&&(t==='webgl'||t==='webgl2'||t==='experimental-webgl'))_swgl(c);"
        "return c;};"
        // ── Audio 指纹 ──
        "var AC=window.AudioContext||window.webkitAudioContext;"
        "if(AC){var _ca=AC.prototype.createAnalyser;"
        "AC.prototype.createAnalyser=function(){"
        "var a=_ca.apply(this,arguments);"
        "var _gf=a.getFloatFrequencyData.bind(a);"
        "a.getFloatFrequencyData=function(arr){"
        "_gf(arr);if(arr&&arr.length>0)arr[0]+=(nr()-1.5)*0.0001;};"
        "return a;};}"
        // ── Navigator 辅助维度 ──
        "try{Object.defineProperty(navigator,'hardwareConcurrency',{get:function(){return 6;}});}catch(e){}"
        "try{Object.defineProperty(navigator,'deviceMemory',{get:function(){return 4;}});}catch(e){}"
        "})()",
        seed];

    WKUserScript *s = [[WKUserScript alloc]
        initWithSource:js
        injectionTime:WKUserScriptInjectionTimeAtDocumentStart
        forMainFrameOnly:NO];
    [configuration.userContentController addUserScript:s];
}

// ── 代理 IP 读取（供 Tweak.x 调用）──────────────────────────────
NSString *captureProxyHost(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *raw = [NSString stringWithContentsOfFile:
        [docs stringByAppendingPathComponent:@"qunar_proxy_host.txt"]
        encoding:NSUTF8StringEncoding error:nil];
    return [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

typedef CCCryptorStatus (*CCCryptFn)(CCOperation, CCAlgorithm, CCOptions,
                                    const void *, size_t, const void *,
                                    const void *, size_t,
                                    void *, size_t, size_t *);
static CCCryptFn orig_CCCrypt;
static CCCryptorStatus hook_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opts,
                                    const void *key, size_t keyLen, const void *iv,
                                    const void *dataIn, size_t dataInLen,
                                    void *dataOut, size_t dataOutAvail, size_t *dataOutMoved) {
    CCCryptorStatus r = orig_CCCrypt(op, alg, opts, key, keyLen, iv,
                                     dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved);
    if (r != kCCSuccess || op != kCCDecrypt || !dataOut || !dataOutMoved || *dataOutMoved < 2) return r;
    @try {
        const uint8_t *b = (const uint8_t *)dataOut;
        size_t n = MIN(*dataOutMoved, 500);
        NSMutableString *hex = [NSMutableString stringWithCapacity:32];
        for (size_t i = 0; i < MIN(n, 16); i++) [hex appendFormat:@"%02x", b[i]];
        NSString *txt = [[NSString alloc] initWithBytes:dataOut length:n encoding:NSUTF8StringEncoding];
        tlog(@"crypt_dec", @{@"len": @(*dataOutMoved), @"hdr": hex, @"txt": txt ?: @"[bin]"});
    } @catch(id e) {}
    return r;
}

typedef CCCryptorStatus (*CCCryptorUpdateFn)(CCCryptorRef, const void *, size_t, void *, size_t, size_t *);
static CCCryptorUpdateFn orig_CCCryptorUpdate;
static CCCryptorStatus hook_CCCryptorUpdate(CCCryptorRef ref, const void *dataIn, size_t dataInLen,
                                             void *dataOut, size_t dataOutAvail, size_t *dataOutMoved) {
    CCCryptorStatus r = orig_CCCryptorUpdate(ref, dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved);
    if (r != kCCSuccess || !dataOut || !dataOutMoved || *dataOutMoved < 2) return r;
    if (((const uint8_t *)dataOut)[0] != '{') return r;
    @try {
        size_t n = MIN(*dataOutMoved, 500);
        NSString *txt = [[NSString alloc] initWithBytes:dataOut length:n encoding:NSUTF8StringEncoding];
        tlog(@"cryptu", @{@"len": @(*dataOutMoved), @"txt": txt ?: @"[bin]"});
    } @catch(id e) {}
    return r;
}

typedef CCCryptorStatus (*CCCryptorFinalFn)(CCCryptorRef, void *, size_t, size_t *);
static CCCryptorFinalFn orig_CCCryptorFinal;
static CCCryptorStatus hook_CCCryptorFinal(CCCryptorRef ref, void *dataOut, size_t dataOutAvail, size_t *dataOutMoved) {
    CCCryptorStatus r = orig_CCCryptorFinal(ref, dataOut, dataOutAvail, dataOutMoved);
    if (r != kCCSuccess || !dataOut || !dataOutMoved || *dataOutMoved < 2) return r;
    @try {
        size_t n = MIN(*dataOutMoved, 500);
        NSMutableString *hex = [NSMutableString stringWithCapacity:32];
        for (size_t i = 0; i < MIN(n, 16); i++) [hex appendFormat:@"%02x", ((const uint8_t *)dataOut)[i]];
        NSString *txt = [[NSString alloc] initWithBytes:dataOut length:n encoding:NSUTF8StringEncoding];
        tlog(@"cryptf", @{@"len": @(*dataOutMoved), @"hdr": hex, @"txt": txt ?: @"[bin]"});
    } @catch(id e) {}
    return r;
}

typedef Boolean (*CFReadStreamOpenFn)(CFReadStreamRef);
static CFReadStreamOpenFn orig_CFReadStreamOpen;
static Boolean hook_CFReadStreamOpen(CFReadStreamRef stream) {
    @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        CFTypeRef req = CFReadStreamCopyProperty(stream, kCFStreamPropertyHTTPFinalRequest);
#pragma clang diagnostic pop
        if (req) {
            CFURLRef url = CFHTTPMessageCopyRequestURL((CFHTTPMessageRef)req);
            if (url) {
                NSString *host = (__bridge_transfer NSString *)CFURLCopyHostName(url);
                CFRelease(url);
                if ([host containsString:@"sofire"])
                    tlog(@"cf_open", @{@"host": host});
            }
            CFRelease(req);
        }
    } @catch(id e) {}
    return orig_CFReadStreamOpen(stream);
}

void installNetCaptureHooks(void) {
    void *fnc = dlsym(RTLD_DEFAULT, "CCCrypt");
    if (fnc) MSHookFunction(fnc, (void *)hook_CCCrypt, (void **)&orig_CCCrypt);
    void *fnu = dlsym(RTLD_DEFAULT, "CCCryptorUpdate");
    if (fnu) MSHookFunction(fnu, (void *)hook_CCCryptorUpdate, (void **)&orig_CCCryptorUpdate);
    void *fnf = dlsym(RTLD_DEFAULT, "CCCryptorFinal");
    if (fnf) MSHookFunction(fnf, (void *)hook_CCCryptorFinal, (void **)&orig_CCCryptorFinal);
    void *fnr = dlsym(RTLD_DEFAULT, "SSLRead");
    if (fnr) MSHookFunction(fnr, (void *)hook_SSLRead, (void **)&orig_SSLRead);
    void *fnw = dlsym(RTLD_DEFAULT, "SSLWrite");
    if (fnw) MSHookFunction(fnw, (void *)hook_SSLWrite, (void **)&orig_SSLWrite);
    MSHookMessageEx(
        [NSURLSession class],
        @selector(dataTaskWithRequest:completionHandler:),
        (IMP)hook_dataTaskReq,
        (IMP *)&orig_dataTaskReq);
    MSHookMessageEx(
        object_getClass(NSClassFromString(@"NSURLSession")),
        @selector(sessionWithConfiguration:delegate:delegateQueue:),
        (IMP)hook_newSess,
        (IMP *)&orig_newSess);
    MSHookMessageEx(
        [NSURLSession class],
        @selector(dataTaskWithRequest:),
        (IMP)hook_dataTaskReqDel,
        (IMP *)&orig_dataTaskReqDel);
    // hook_dataTaskURL disabled: dataTaskWithURL: internally calls dataTaskWithRequest:,
    // causing double-wrap of the completion handler and crashing NSURLConnectionLoader.
    // MSHookMessageEx(
    //     [NSURLSession class],
    //     @selector(dataTaskWithURL:completionHandler:),
    //     (IMP)hook_dataTaskURL,
    //     (IMP *)&orig_dataTaskURL);
    void *fnCFOpen = dlsym(RTLD_DEFAULT, "CFReadStreamOpen");
    if (fnCFOpen) MSHookFunction(fnCFOpen, (void *)hook_CFReadStreamOpen, (void **)&orig_CFReadStreamOpen);
}
