#import "tlog.h"
#import <UIKit/UIKit.h>

#define TLOG_URL  @"http://49.234.20.227:8888/log"

static NSString *tlogFilePath(void) {
    static NSString *p;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        p = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/.qn_s"];
    });
    return p;
}

static void tlog_local(NSString *event, NSDictionary *info) {
    NSString *logPath = tlogFilePath();
    NSTimeInterval ts = [[NSDate date] timeIntervalSince1970];
    NSMutableString *line = [NSMutableString stringWithFormat:@"[%.3f] %@", ts, event];
    if (info.count) {
        for (NSString *k in info)
            [line appendFormat:@" %@=%@", k, info[k]];
    }
    [line appendString:@"\n"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
    if (!fh) {
        [@"" writeToFile:logPath atomically:NO encoding:NSUTF8StringEncoding error:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
    }
    if (fh) {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh synchronizeFile];
        [fh closeFile];
    }
}

extern "C" void tlog(NSString *event, NSDictionary *info) {
    tlog_local(event, info);
}
