// hades_filter.x — 过滤 hadesIdentityJson 中的用户画像标签
#import <Foundation/Foundation.h>
#import "tlog.h"

static NSMutableDictionary *parseDict(NSString *s) {
    if (![s isKindOfClass:[NSString class]]) return nil;
    NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
    if (!d) return nil;
    id obj = [NSJSONSerialization JSONObjectWithData:d options:NSJSONReadingMutableContainers error:nil];
    return [obj isKindOfClass:[NSDictionary class]] ? [obj mutableCopy] : nil;
}

static NSString *toJson(id obj) {
    NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
}

static void dumpBp(NSString *params, id tValue) {
    if (!tValue)
        tlog(@"bp_tv", @{@"cls": @"nil"});
    else if ([tValue isKindOfClass:[NSString class]])
        tlog(@"bp_tv", @{@"cls": @"str", @"len": @([(NSString *)tValue length]),
                         @"pfx": [(NSString *)tValue substringToIndex:MIN(32u, (unsigned)[(NSString *)tValue length])]});
    else if ([tValue isKindOfClass:[NSData class]])
        tlog(@"bp_tv", @{@"cls": @"data", @"len": @([(NSData *)tValue length])});
    else
        tlog(@"bp_tv", @{@"cls": NSStringFromClass([tValue class])});
    NSMutableDictionary *outer = parseDict(params);
    tlog(@"bp_outer", @{@"keys": [outer allKeys] ?: @[]});
    NSMutableDictionary *extra = parseDict(outer[@"extra"]);
    tlog(@"bp_extra", @{@"keys": [extra allKeys] ?: @[]});
    for (NSString *k in extra) {
        id v = extra[k];
        if (![v isKindOfClass:[NSString class]]) continue;
        if ([(NSString *)v length] >= 100) continue;
        if ([k isEqualToString:@"hadesIdentityJson"]) continue;
        tlog(@"bp_ev", @{@"k": k, @"v": v});
    }
}

static NSString *filterHadesParams(NSString *params) {
    @try {
        NSMutableDictionary *outer = parseDict(params);
        NSMutableDictionary *extra = parseDict(outer[@"extra"]);
        NSString *hadesStr = extra[@"hadesIdentityJson"];
        if (!hadesStr) return nil;
        NSData *hadesData = [hadesStr dataUsingEncoding:NSUTF8StringEncoding];
        if (!hadesData) return nil;
        NSArray *hades = [NSJSONSerialization JSONObjectWithData:hadesData options:0 error:nil];
        if (![hades isKindOfClass:[NSArray class]]) return nil;
        NSSet *drop = [NSSet setWithObjects:@"upliftUserL3", @"newUserHighUplift", nil];
        NSArray *filtered = [hades filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSDictionary *item, id _) {
            return ![drop containsObject:item[@"code"]];
        }]];
        if (filtered.count == hades.count) return nil;
        tlog(@"hades_filter", @{@"before": @(hades.count), @"after": @(filtered.count)});
        extra[@"hadesIdentityJson"] = toJson(filtered);
        outer[@"extra"] = toJson(extra);
        return toJson(outer);
    } @catch (NSException *ex) {
        tlog(@"hades_filter_err", @{@"ex": ex.reason ?: @"?"});
        return nil;
    }
}

%group HadesFilter

%hook SearchNetParamEncryPtion
+ (void)addEncryptedBusinessParameters:(NSString *)params tValue:(id)tValue {
    if (!params) { %orig; return; }
    NSString *flag = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/qunar_test_filter_hades"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:flag]) { %orig; return; }
    dumpBp(params, tValue);
    NSString *modified = filterHadesParams(params);
    if (!modified) { tlog(@"hades_filter", @{@"skip": @"no_target"}); %orig; return; }
    %orig(modified, tValue);
}
%end

%end

%ctor {
    @autoreleasepool {
        if (![[[NSBundle mainBundle] bundleIdentifier] isEqualToString:@"com.qunar.iphoneclient8"]) return;
        Class cls = NSClassFromString(@"SearchNetParamEncryPtion");
        tlog(@"hades_ctor", @{@"cls": @(cls != nil)});
        if (!cls) return;
        %init(HadesFilter);
    }
}
