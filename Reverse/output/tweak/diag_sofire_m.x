// diag_sofire_m.x — 一次性诊断：确认 sofire POST /m/ body 是否加密，用完删
#import <Foundation/Foundation.h>
#import "tlog.h"

%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)req
                            completionHandler:(id)handler {
    NSString *url = req.URL.absoluteString ?: @"";
    if ([url containsString:@"sofire.baidu.com"] && [url containsString:@"/m/"]) {
        NSData *body = req.HTTPBody;
        NSString *bodyStr = nil;
        if (body.length > 0) {
            bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
            if (!bodyStr) {
                bodyStr = [NSString stringWithFormat:@"[base64] %@",
                           [body base64EncodedStringWithOptions:0]];
            }
        } else if (req.HTTPBodyStream) {
            bodyStr = @"[stream_upload]";
        } else {
            bodyStr = @"[nil]";
        }
        NSString *prefix = [bodyStr substringToIndex:MIN((NSUInteger)300, bodyStr.length)];
        tlog(@"sofire_m", @{
            @"url": url,
            @"method": req.HTTPMethod ?: @"?",
            @"body_len": @(body.length),
            @"body": prefix
        });
        NSArray<NSNumber *> *addrs = [NSThread callStackReturnAddresses];
        intptr_t slide = 0;
        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            const char *n = _dyld_get_image_name(i);
            if (n && strstr(n, "QunariPhone_Cook_CM")) {
                slide = _dyld_get_image_vmaddr_slide(i);
                break;
            }
        }
        NSMutableString *st = [NSMutableString string];
        for (NSNumber *a in addrs) {
            uint64_t off = [a unsignedLongLongValue] - 0x100000000ULL - (uint64_t)slide;
            [st appendFormat:@"0x%llx\n", off];
        }
        tlog(@"sofire_m_stack", @{@"st": st});
    }
    return %orig;
}
%end
