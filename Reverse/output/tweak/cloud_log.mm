#import <Foundation/Foundation.h>
#import "cloud_log.h"

static NSString *const kURL = @"http://49.234.20.227:8888/log";
static NSURLSession *gSess;
static dispatch_once_t gSessOnce;

static NSURLSession *cloudSess(void) {
    dispatch_once(&gSessOnce, ^{
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cfg.timeoutIntervalForRequest = 5;
        gSess = [NSURLSession sessionWithConfiguration:cfg];
    });
    return gSess;
}

void cloudLog(NSString *event, NSDictionary *data) {
    NSMutableDictionary *p = [NSMutableDictionary dictionaryWithDictionary:data ?: @{}];
    p[@"event"] = event ?: @"?";
    p[@"src"] = @"tweak";
    NSData *body = [NSJSONSerialization dataWithJSONObject:p options:0 error:nil];
    if (!body) return;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:kURL]];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = body;
    [[cloudSess() dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {}] resume];
}
