#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <Security/SecureTransport.h>
#import <dlfcn.h>
#import <zlib.h>
#import <substrate.h>
#import "tlog.h"
#import "net_capture.h"

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
           [s containsString:@"错误"]      || [s containsString:@"失败"];
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
            NSString *s = [[NSString alloc] initWithBytes:data length:MIN(dataLen, 300) encoding:NSUTF8StringEncoding];
            if (s && ([s containsString:@"qunar.com"] || [s containsString:@"passport"] ||
                      [s containsString:@"risk"]))
                tlog(@"ssl_req", @{@"s": s.length > 300 ? [s substringToIndex:300] : s});
        }
    } @catch(id e) {}
    return orig_SSLWrite(ctx, data, dataLen, processed);
}

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
        if ([u containsString:@"qunar.com"] && ![u containsString:@"slugger"]) {
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

- (void)URLSession:(NSURLSession *)sess task:(NSURLSessionTask *)t didCompleteWithError:(NSError *)e {
    @try {
        NSString *u = t.currentRequest.URL.absoluteString ?: @"";
        if ([u containsString:@"qunar.com"] && ![u containsString:@"slugger"])
            tlog(@"resp_done", @{
                @"u": u.length > 120 ? [u substringToIndex:120] : u,
                @"e": e.localizedDescription ?: @""
            });
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
    if (d) {
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
        if ([u containsString:@"qunar"]) {
            tlog(@"req_all", @{@"u": u.length > 200 ? [u substringToIndex:200] : u,
                               @"m": req.HTTPMethod ?: @"GET"});
        }
    } @catch(id e) {}
    return orig_dataTaskReq(self, cmd, req, handler);
}

void installNetCaptureHooks(void) {
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
}
