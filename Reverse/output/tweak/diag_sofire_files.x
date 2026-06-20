// diag_sofire_files.x — 诊断：
// 1. hook NSData writeToFile: 捕获 hsarcerifos 目录写入（启动时采集阶段）
// 2. hook blockPostBeforeRecvc: 读目录内容（POST 前）
#import <Foundation/Foundation.h>
#import "tlog.h"

static void logDataAtPath(NSString *path, NSData *data) {
    if (!path || !data) return;
    if ([path rangeOfString:@"hsarcerifos"].location == NSNotFound) return;
    NSString *rel = path.lastPathComponent;
    NSString *txt = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (txt) {
        NSString *snippet = txt.length > 2000 ? [txt substringToIndex:2000] : txt;
        tlog(@"sf_write_txt", @{@"f": rel, @"len": @(data.length), @"v": snippet});
    } else {
        NSString *b64 = [data base64EncodedStringWithOptions:0];
        NSString *b64s = b64.length > 2000 ? [b64 substringToIndex:2000] : b64;
        tlog(@"sf_write_bin", @{@"f": rel, @"len": @(data.length), @"b64": b64s});
    }
}

// ── NSData write hooks ──────────────────────────────────────────────────────

%hook NSData

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)flag {
    logDataAtPath(path, self);
    return %orig;
}

- (BOOL)writeToFile:(NSString *)path options:(NSDataWritingOptions)opt error:(NSError **)err {
    logDataAtPath(path, self);
    return %orig;
}

%end

// ── NSFileManager createFileAtPath:contents:attributes: ─────────────────────

%hook NSFileManager

- (BOOL)createFileAtPath:(NSString *)path
                contents:(NSData *)data
              attributes:(NSDictionary *)attr {
    logDataAtPath(path, data);
    return %orig;
}

%end

// ── blockPostBeforeRecvc: — 读目录（此时文件应已写入）────────────────────────

%hook SSMPTypeNodeMgrg

+ (void)blockPostBeforeRecvc:(id)arg {
    @try {
        NSString *dirPath = [arg description];
        NSFileManager *fm = [NSFileManager defaultManager];
        NSError *err = nil;
        NSArray<NSString *> *items = [fm subpathsOfDirectoryAtPath:dirPath error:&err];
        tlog(@"sf_files", @{
            @"dir": dirPath ?: @"nil",
            @"count": @(items.count),
            @"err": err.localizedDescription ?: @"none"
        });
        for (NSString *rel in items) {
            NSString *full = [dirPath stringByAppendingPathComponent:rel];
            NSData *data = [NSData dataWithContentsOfFile:full];
            if (data) logDataAtPath(full, data);
        }
    } @catch (NSException *ex) {
        tlog(@"sf_files_err", @{@"ex": ex.reason ?: @"?"});
    }
    %orig;
}

%end
