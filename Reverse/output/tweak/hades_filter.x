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

static NSString *valStr(id v) {
    if ([v isKindOfClass:[NSString class]])
        return [(NSString *)v substringToIndex:MIN((NSUInteger)80, [(NSString *)v length])];
    if ([v isKindOfClass:[NSNumber class]])
        return [(NSNumber *)v stringValue];
    return NSStringFromClass([v class]) ?: @"(nil)";
}

static void dumpHcFields(id hcObj) {
    if (![hcObj isKindOfClass:[NSDictionary class]]) return;
    for (NSString *k in (NSDictionary *)hcObj)
        tlog(@"hc_kv", @{@"k": k, @"v": valStr(((NSDictionary *)hcObj)[k])});
}

static void dumpHlistFields(NSMutableDictionary *outer) {
    id vt = outer[@"vtoken"];
    tlog(@"hlist_vt", @{@"v": vt ? valStr(vt) : @"nil"});
    id ab = outer[@"abTestSlot"];
    if ([ab isKindOfClass:[NSDictionary class]]) {
        NSString *abJson = toJson(ab) ?: @"nil";
        tlog(@"hlist_ab", @{@"json": [abJson substringToIndex:MIN((NSUInteger)2000, abJson.length)]});
    } else {
        tlog(@"hlist_ab", @{@"v": valStr(ab)});
    }
    dumpHcFields(outer[@"hc"]);
}

static void dumpBp(NSString *params, id tValue) {
    NSMutableDictionary *outer = parseDict(params);
    tlog(@"bp_outer", @{@"keys": [[outer allKeys] componentsJoinedByString:@","] ?: @""});
    NSMutableDictionary *extra = parseDict(outer[@"extra"]);
    tlog(@"bp_extra", @{@"keys": [[extra allKeys] componentsJoinedByString:@","] ?: @""});
    if (outer[@"hotelSeqs"] || outer[@"vtoken"]) { dumpHlistFields(outer); return; }
    if (!extra[@"hadesIdentityJson"]) return;
    tlog(@"bp_tv", @{@"v": [tValue isKindOfClass:[NSString class]] ? tValue : @"?"});
    for (NSString *k in @[@"vtoken", @"hc", @"resultExtraInfo"]) {
        id v = outer[k];
        if (!v) continue;
        tlog(@"bp_ov", @{@"k": k, @"v": valStr(v)});
    }
    for (NSString *k in extra) {
        if ([k isEqualToString:@"hadesIdentityJson"]) continue;
        tlog(@"bp_ev", @{@"k": k, @"v": valStr(extra[k])});
    }
}

static NSString *filterHadesParams(NSString *params) {
    @try {
        NSMutableDictionary *outer = parseDict(params);
        if (!outer) return nil;
        BOOL modified = NO;

        id rawSlot = outer[@"abTestSlot"];
        if ([rawSlot isKindOfClass:[NSDictionary class]] && rawSlot[@"priceAction"]) {
            NSMutableDictionary *abSlot = [rawSlot mutableCopy];
            abSlot[@"priceAction"] = @"A";
            outer[@"abTestSlot"] = abSlot;
            tlog(@"ab_patched", @{@"orig": rawSlot[@"priceAction"]});
            modified = YES;
        }

        NSMutableDictionary *extra = parseDict(outer[@"extra"]);
        NSString *hadesStr = extra[@"hadesIdentityJson"];
        if (hadesStr) {
            NSData *hadesData = [hadesStr dataUsingEncoding:NSUTF8StringEncoding];
            NSArray *hades = hadesData ? [NSJSONSerialization JSONObjectWithData:hadesData options:0 error:nil] : nil;
            if ([hades isKindOfClass:[NSArray class]]) {
                NSSet *drop = [NSSet setWithObjects:@"upliftUserL3", @"newUserHighUplift", nil];
                NSArray *filtered = [hades filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSDictionary *item, id _) {
                    return ![drop containsObject:item[@"code"]];
                }]];
                if (filtered.count != hades.count) {
                    tlog(@"hades_filter", @{@"before": @(hades.count), @"after": @(filtered.count)});
                    extra[@"hadesIdentityJson"] = toJson(filtered);
                    outer[@"extra"] = toJson(extra);
                    modified = YES;
                }
            }
        }

        return modified ? toJson(outer) : nil;
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
