#import <Foundation/Foundation.h>
#import "tlog.h"
#import <sys/sysctl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#import <CoreFoundation/CoreFoundation.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <dlfcn.h>
#import <mach/mach.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#import <substrate.h>
#import <objc/runtime.h>
#import "bypass.h"
#import "profile.h"
#import "net_capture.h"
#import <CommonCrypto/CommonDigest.h>

static const char * const kJailPaths[] = {
    "/var/jb", "/private/var/jb",
    "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
    "/Library/MobileSubstrate", "/usr/sbin/sshd", "/usr/bin/ssh",
    "/etc/apt", "/private/var/lib/apt", "/private/var/stash",
    "/usr/lib/TweakInject", "/usr/lib/ellekit", "/usr/lib/substrate",
    "/private/preboot", "systemhook", "ElleKit", "frida", "FridaGadget",
    "cynject", "substitute",
    "/bin/bash", "/bin/sh", "/var/lib/cydia", "/var/cache/apt",
    NULL
};
static const char * const kInjKw[] = {
    "frida", "cynject", NULL
};

static const char * const kHideDylibs[] = {
    "QunarNewDevice", "ElleKit", "ellekit", "TweakInject", "tweakinject",
    "systemhook", "cynject", "frida", "substrate", "MobileSubstrate",
    "cycript", "dopamine", "procursus", ".fakelib", NULL
};

static BOOL isJailPath(const char *p) {
    if (!p) return NO;
    for (int i = 0; kJailPaths[i]; i++)
        if (strstr(p, kJailPaths[i])) return YES;
    return NO;
}
static BOOL isInjDylib(const char *n) {
    if (!n) return NO;
    for (int i = 0; kInjKw[i]; i++)
        if (strcasestr(n, kInjKw[i])) return YES;
    return NO;
}

static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int hook_ptrace(int req, pid_t pid, caddr_t addr, int data) {
    return (req == 31) ? 0 : orig_ptrace(req, pid, addr, data);
}

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hook_sysctl(int *mib, u_int nl, void *old, size_t *osz, void *n, size_t nsz) {
    int r = orig_sysctl(mib, nl, old, osz, n, nsz);
    if (r == 0 && nl >= 2 && mib[0] == 1 && mib[1] == 14 && old)
        *(uint32_t *)((char *)old + 32) &= ~0x800u;
    return r;
}

static uint32_t (*orig_dyld_count)(void);
static const char *(*orig_dyld_name)(uint32_t);
static const char *(*orig_class_getImageName)(Class);

static BOOL shouldHideDylib(const char *name) {
    if (!name) return NO;
    for (int i = 0; kHideDylibs[i]; i++)
        if (strcasestr(name, kHideDylibs[i])) return YES;
    return NO;
}

static uint32_t hook_dyld_count(void) {
    uint32_t total = orig_dyld_count();
    uint32_t hidden = 0;
    for (uint32_t i = 0; i < total; i++)
        if (shouldHideDylib(orig_dyld_name(i))) hidden++;
    return total - hidden;
}

static const char *hook_class_getImageName(Class cls) {
    const char *n = orig_class_getImageName(cls);
    return n ?: "";
}

static CFAbsoluteTime gStartTime = 0;
static int32_t gInTlog = 0;
static int gDyldLogDone = 0;
static int gImgNamesLogDone = 0;
static const char **(*orig_objc_copyImageNames)(unsigned int *);
static const char **hook_objc_copyImageNames_diag(unsigned int *outCount) {
    const char **result = orig_objc_copyImageNames(outCount);
    if (result && outCount && __sync_val_compare_and_swap(&gImgNamesLogDone, 0, 1) == 0) {
        unsigned int count = *outCount;
        tlog(@"img_names_first", @{@"n": @(count)});
        for (unsigned int i = 0; i < count; i++) {
            if (result[i] && shouldHideDylib(result[i]))
                tlog(@"img_names_hidden", @{@"name": @(result[i])});
        }
    }
    return result;
}
static const char *hook_dyld_name(uint32_t idx) {
    uint32_t total = orig_dyld_count();
    // 只在第一次枚举时记录哪些被过滤
    if (idx == 0 && __sync_val_compare_and_swap(&gDyldLogDone, 0, 1) == 0) {
        for (uint32_t i = 0; i < total; i++) {
            const char *n = orig_dyld_name(i);
            if (shouldHideDylib(n))
                tlog(@"dyld_hidden", @{@"name": @(n ?: "")});
        }
        tlog(@"dyld_enum", @{@"total": @(total)});
    }
    uint32_t visible = 0;
    for (uint32_t i = 0; i < total; i++) {
        const char *name = orig_dyld_name(i);
        if (shouldHideDylib(name)) continue;
        if (visible == idx) return name ?: "";
        visible++;
    }
    const char *r = orig_dyld_name(idx);
    return r ?: "";
}

static DIR *(*orig_opendir)(const char *);
static DIR *hook_opendir(const char *p) {
    if (isJailPath(p)) { errno = ENOENT; return NULL; }
    return orig_opendir(p);
}

static int (*orig_readlink)(const char *, char *, size_t);
static int hook_readlink(const char *p, char *b, size_t s) {
    if (isJailPath(p)) { errno = ENOENT; return -1; }
    return orig_readlink(p, b, s);
}

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int hook_connect(int fd, const struct sockaddr *sa, socklen_t sl) {
    if (sa && sa->sa_family == AF_INET) {
        uint16_t port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
        if (port == 22 || port == 44 || port == 4444 ||
            port == 27042 || port == 27043 || port == 46952) {
            tlog(@"connect_blocked", @{@"port": @(port)});
            errno = ECONNREFUSED;
            return -1;
        }
    }
    return orig_connect(fd, sa, sl);
}

static int (*orig_access)(const char *, int);
static int hook_access(const char *p, int m) {
    if (isJailPath(p)) return -1;
    int r = orig_access(p, m);
    if (r == 0 && p && !gInTlog && gStartTime > 0 && (CFAbsoluteTimeGetCurrent() - gStartTime) < 2.0) {
        if (__sync_bool_compare_and_swap(&gInTlog, 0, 1)) {
            tlog(@"access_ok", @{@"p": @(p)});
            gInTlog = 0;
        }
    }
    return r;
}

static FILE *(*orig_fopen)(const char *, const char *);
static FILE *hook_fopen(const char *p, const char *m) { return isJailPath(p) ? NULL : orig_fopen(p, m); }

static int (*orig_stat)(const char *, struct stat *);
static int hook_stat(const char *p, struct stat *s) {
    if (isJailPath(p)) return -1;
    int r = orig_stat(p, s);
    if (r == 0 && p && !gInTlog && gStartTime > 0 && (CFAbsoluteTimeGetCurrent() - gStartTime) < 2.0) {
        if (__sync_bool_compare_and_swap(&gInTlog, 0, 1)) {
            tlog(@"stat_ok", @{@"p": @(p)});
            gInTlog = 0;
        }
    }
    return r;
}

static int (*orig_stat64)(const char *, void *);
static int hook_stat64(const char *p, void *s) { return isJailPath(p) ? -1 : orig_stat64(p, s); }

static int (*orig_lstat)(const char *, struct stat *);
static int hook_lstat(const char *p, struct stat *s) { return isJailPath(p) ? -1 : orig_lstat(p, s); }

static int (*orig_lstat64)(const char *, void *);
static int hook_lstat64(const char *p, void *s) { return isJailPath(p) ? -1 : orig_lstat64(p, s); }

static pid_t (*orig_fork)(void);
static pid_t hook_fork(void) { return -1; }

static char *(*orig_getenv)(const char *);
static char *hook_getenv(const char *k) {
    if (k && (!strcmp(k, "DYLD_INSERT_LIBRARIES") || !strcmp(k, "DYLD_LIBRARY_PATH")))
        return NULL;
    return orig_getenv(k);
}

static FILE *(*orig_popen)(const char *, const char *);
static FILE *hook_popen(const char *c, const char *m) { return NULL; }
static int (*orig_system)(const char *);
static int hook_system(const char *c) { return 0; }

static void *(*orig_dlopen)(const char *, int);
static void *hook_dlopen(const char *p, int f) { return isInjDylib(p) ? NULL : orig_dlopen(p, f); }

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int hook_sysctlbyname(const char *n, void *o, size_t *sz, void *ne, size_t nsz) {
    if (n && strstr(n, "kern.proc.pid")) return -1;
    int r = orig_sysctlbyname(n, o, sz, ne, nsz);
    if (r != 0 || !o || !sz || !n) return r;
    if (gMachine && (strcmp(n, "hw.machine") == 0 || strcmp(n, "hw.model") == 0)) {
        const char *m = [gMachine UTF8String];
        strlcpy((char *)o, m, *sz);
        *sz = strlen(m) + 1;
    } else if (gBootSessionUUID && strcmp(n, "kern.bootsessionuuid") == 0) {
        const char *u = [gBootSessionUUID UTF8String];
        strlcpy((char *)o, u, *sz);
        *sz = strlen(u) + 1;
    } else if (gHardwareUUID && (strcmp(n, "kern.hostuuid") == 0 || strcmp(n, "hw.uuid") == 0)) {
        const char *u = [gHardwareUUID UTF8String];
        strlcpy((char *)o, u, *sz);
        *sz = strlen(u) + 1;
    }
    return r;
}

static CFTypeRef (*orig_IORegCreateCFProp)(mach_port_t, CFStringRef, CFAllocatorRef, uint32_t);
static CFTypeRef hook_IORegCreateCFProp(mach_port_t entry, CFStringRef key, CFAllocatorRef alloc, uint32_t opts) {
    if (!key) return orig_IORegCreateCFProp(entry, key, alloc, opts);
    if (gHardwareUUID && CFStringCompare(key, CFSTR("IOPlatformUUID"), 0) == kCFCompareEqualTo)
        return CFStringCreateCopy(alloc ?: kCFAllocatorDefault, (__bridge CFStringRef)gHardwareUUID);
    if (gSerialNumber && CFStringCompare(key, CFSTR("IOPlatformSerialNumber"), 0) == kCFCompareEqualTo)
        return CFStringCreateCopy(alloc ?: kCFAllocatorDefault, (__bridge CFStringRef)gSerialNumber);
    CFTypeRef r = orig_IORegCreateCFProp(entry, key, alloc, opts);
    NSString *ks = (__bridge NSString *)key;
    if ([ks hasPrefix:@"IOPlatform"] || [ks containsString:@"Serial"] || [ks containsString:@"IMEI"])
        tlog(@"iokit_read", @{@"k": ks, @"v": r ? [NSString stringWithFormat:@"%@", (__bridge id)r] : @"nil"});
    return r;
}

#if defined(__arm64e__)
#import <ptrauth.h>
#define _STRIP(p) ptrauth_strip((void*)(p), ptrauth_key_function_pointer)
#else
#define _STRIP(p) ((void*)(p))
#endif
#define MH(sym, hook, orig) do { void *_f=dlsym(RTLD_DEFAULT,sym); if(_f) MSHookFunction(_STRIP(_f),(void*)(hook),(void**)(orig)); } while(0)

static kern_return_t (*orig_task_info)(task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t *);
static kern_return_t hook_task_info(task_name_t t, task_flavor_t f, task_info_t info, mach_msg_type_number_t *cnt) {
    kern_return_t r = orig_task_info(t, f, info, cnt);
    if (r == KERN_SUCCESS && f == 11 /* TASK_DYLD_INFO */ && info && cnt && *cnt >= 5)
        memset(info, 0, 5 * sizeof(integer_t));
    return r;
}

static kern_return_t (*orig_task_exc_ports)(task_t, exception_mask_t, exception_mask_array_t, mach_msg_type_number_t *, exception_handler_array_t, exception_behavior_array_t, exception_flavor_array_t);
static kern_return_t hook_task_exc_ports(task_t t, exception_mask_t m, exception_mask_array_t masks, mach_msg_type_number_t *cnt, exception_handler_array_t h, exception_behavior_array_t b, exception_flavor_array_t flv) {
    if (cnt) *cnt = 0;
    return KERN_SUCCESS;
}

static void (*orig_exit)(int);
static void hook_exit(int code) { tlog(@"exit_blocked", @{@"code": @(code)}); }

static void (*orig__exit)(int);
static void hook__exit(int code) { tlog(@"_exit_blocked", @{@"code": @(code)}); }

static void (*orig_abort)(void);
static void hook_abort(void) { tlog(@"abort_blocked", nil); }

static int (*orig_kill)(pid_t, int);
static int hook_kill(pid_t pid, int sig) {
    if (pid == getpid() && (sig == SIGKILL || sig == SIGTERM)) {
        tlog(@"kill_blocked", @{@"sig": @(sig)});
        return 0;
    }
    return orig_kill(pid, sig);
}

static BOOL (*orig_fileExists)(id, SEL, NSString *);
static BOOL hook_fileExists(id self, SEL cmd, NSString *path) {
    if (path && isJailPath(path.UTF8String)) return NO;
    return orig_fileExists(self, cmd, path);
}
static BOOL (*orig_fileExistsIsDir)(id, SEL, NSString *, BOOL *);
static BOOL hook_fileExistsIsDir(id self, SEL cmd, NSString *path, BOOL *isDir) {
    if (path && isJailPath(path.UTF8String)) return NO;
    return orig_fileExistsIsDir(self, cmd, path, isDir);
}

static void hookAntiDebug(void) {
    MH("ptrace",  hook_ptrace,  &orig_ptrace);
    MH("sysctl",  hook_sysctl,  &orig_sysctl);
    MH("fork",    hook_fork,    &orig_fork);
    MH("_dyld_image_count",    hook_dyld_count,              &orig_dyld_count);
    MH("_dyld_get_image_name", hook_dyld_name,               &orig_dyld_name);
    MH("class_getImageName",   hook_class_getImageName,      &orig_class_getImageName);
    MH("objc_copyImageNames",  hook_objc_copyImageNames_diag, &orig_objc_copyImageNames);
    MH("sysctlbyname", hook_sysctlbyname, &orig_sysctlbyname);
    MH("task_info", hook_task_info, &orig_task_info);
    MH("task_get_exception_ports", hook_task_exc_ports, &orig_task_exc_ports);
    MH("exit",  hook_exit,  &orig_exit);
    MH("_exit", hook__exit, &orig__exit);
    MH("abort", hook_abort, &orig_abort);
    MH("kill",  hook_kill,  &orig_kill);
}


static void hookEnvDetect(void) {
    MH("connect",   hook_connect,   &orig_connect);
    MH("opendir",   hook_opendir,   &orig_opendir);
    MH("readlink",  hook_readlink,  &orig_readlink);
    MH("access",    hook_access,    &orig_access);
    MH("fopen",    hook_fopen,    &orig_fopen);
    MH("stat",     hook_stat,     &orig_stat);
    MH("stat64",   hook_stat64,   &orig_stat64);
    MH("lstat",    hook_lstat,    &orig_lstat);
    MH("lstat64",  hook_lstat64,  &orig_lstat64);
    MH("getenv",   hook_getenv,   &orig_getenv);
    MH("popen",    hook_popen,    &orig_popen);
    MH("system",   hook_system,   &orig_system);
    MH("dlopen",   hook_dlopen,   &orig_dlopen);
}

// SSL pinning bypass — allows mitmproxy MITM
static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef, SecTrustResultType *);
static OSStatus hook_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultProceed;
    return errSecSuccess;
}
static bool (*orig_SecTrustEvaluateWithError)(SecTrustRef, CFErrorRef *);
static bool hook_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    if (error) *error = NULL;
    return true;
}

void installSSLBypassAlways(void) {
    MH("SecTrustEvaluate",          hook_SecTrustEvaluate,          &orig_SecTrustEvaluate);
    MH("SecTrustEvaluateWithError", hook_SecTrustEvaluateWithError, &orig_SecTrustEvaluateWithError);
}

void installBypassHooks(void) {
    hookAntiDebug();
    hookEnvDetect();
    dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    MH("IORegistryEntryCreateCFProperty", hook_IORegCreateCFProp, &orig_IORegCreateCFProp);
    MH("SecTrustEvaluate", hook_SecTrustEvaluate, &orig_SecTrustEvaluate);
    MH("SecTrustEvaluateWithError", hook_SecTrustEvaluateWithError, &orig_SecTrustEvaluateWithError);
    MSHookMessageEx(
        NSClassFromString(@"NSFileManager"),
        @selector(fileExistsAtPath:),
        (IMP)hook_fileExists,
        (IMP *)&orig_fileExists);
    MSHookMessageEx(
        NSClassFromString(@"NSFileManager"),
        @selector(fileExistsAtPath:isDirectory:),
        (IMP)hook_fileExistsIsDir,
        (IMP *)&orig_fileExistsIsDir);
    installNetCaptureHooks();
    gStartTime = CFAbsoluteTimeGetCurrent();
    tlog(@"bypass_installed", nil);
}
