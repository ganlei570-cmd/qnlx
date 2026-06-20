// diag_sofire_files.x — 诊断：读取 blockPostBeforeRecvc: 入参目录的文件（%orig 前读，避免被删）
#import <Foundation/Foundation.h>
#import "tlog.h"

%hook SSMPTypeNodeMgrg

+ (void)blockPostBeforeRecvc:(id)arg {
    @try {
        NSString *dirPath = [arg description];
        NSFileManager *fm = [NSFileManager defaultManager];
        NSError *err = nil;
        NSArray<NSString *> *items = [fm subpathsOfDirectoryAtPath:dirPath error:&err];
        if (!items || items.count == 0) {
            tlog(@"sf_files", @{@"dir": dirPath ?: @"nil", @"count": @0, @"err": err.localizedDescription ?: @"none"});
        } else {
            tlog(@"sf_files", @{@"dir": dirPath, @"count": @(items.count)});
            for (NSString *rel in items) {
                NSString *full = [dirPath stringByAppendingPathComponent:rel];
                NSError *readErr = nil;
                NSString *txt = [NSString stringWithContentsOfFile:full
                                                          encoding:NSUTF8StringEncoding
                                                             error:&readErr];
                if (txt) {
                    // text file — log first 2000 chars
                    NSString *snippet = txt.length > 2000 ? [txt substringToIndex:2000] : txt;
                    tlog(@"sf_file_txt", @{@"f": rel, @"len": @(txt.length), @"v": snippet});
                } else {
                    // binary — log as base64
                    NSData *data = [NSData dataWithContentsOfFile:full];
                    if (data) {
                        NSString *b64 = [data base64EncodedStringWithOptions:0];
                        NSString *b64snippet = b64.length > 2000 ? [b64 substringToIndex:2000] : b64;
                        tlog(@"sf_file_bin", @{@"f": rel, @"len": @(data.length), @"b64": b64snippet});
                    } else {
                        tlog(@"sf_file_bin", @{@"f": rel, @"len": @(-1), @"b64": @"unreadable"});
                    }
                }
            }
        }
    } @catch (NSException *ex) {
        tlog(@"sf_files_err", @{@"ex": ex.reason ?: @"?"});
    }
    %orig;
}

%end
