// hades_filter.x — 过滤 hadesIdentityJson 中的用户画像标签
#import <Foundation/Foundation.h>
#import "tlog.h"

static NSMutableDictionary *parseDict(NSString *s) {
    NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
    return [[NSJSONSerialization JSONObjectWithData:d options:NSJSONReadingMutableContainers error:nil] mutableCopy];
}

static NSString *toJson(id obj) {
    NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
}

static NSString *filterHadesParams(NSString *params) {
    NSMutableDictionary *outer = parseDict(params);
    NSMutableDictionary *extra = parseDict(outer[@"extra"]);
    NSString *hadesStr = extra[@"hadesIdentityJson"];
    if (!hadesStr) return nil;
    NSArray *hades = [NSJSONSerialization JSONObjectWithData:[hadesStr dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
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
}

%group HadesFilter

%hook SearchNetParamEncryPtion
+ (void)addEncryptedBusinessParameters:(NSString *)params tValue:(id)tValue {
    NSString *flag = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/qunar_test_filter_hades"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:flag]) { %orig; return; }
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
