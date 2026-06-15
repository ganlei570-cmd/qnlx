#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import "tlog.h"
#import "dump.h"

static bool vmread(vm_address_t src, void *dst, vm_size_t size) {
    // XO pages (execute-only) block vm_read_overwrite; temporarily add read permission
    vm_protect(mach_task_self(), src, size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    vm_size_t got = size;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), src, size,
                                          (vm_address_t)dst, &got);
    vm_protect(mach_task_self(), src, size, FALSE, VM_PROT_EXECUTE);
    return kr == KERN_SUCCESS && got == size;
}

void dumpMainBinary(void) {
    tlog(@"dump_enter", nil);
    @try {
        uint32_t imgCount = _dyld_image_count();
        int32_t mainIdx = -1;
        for (uint32_t i = 0; i < imgCount; i++) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, "QunariPhone_Cook_CM")
                && !strstr(name, ".dylib") && !strstr(name, ".framework")) {
                mainIdx = (int32_t)i;
                break;
            }
        }
        if (mainIdx < 0) { tlog(@"dump_err", @{@"e": @"not found"}); return; }

        intptr_t slide = _dyld_get_image_vmaddr_slide((uint32_t)mainIdx);
        const char *binaryPath = _dyld_get_image_name((uint32_t)mainIdx);
        tlog(@"dump_start", @{@"slide": [NSString stringWithFormat:@"0x%lx", (long)slide],
                               @"path": @(binaryPath)});

        // 从磁盘读正确的 header（未被 Dopamine 裁剪，header 不在 FairPlay 加密范围内）
        FILE *diskFile = fopen(binaryPath, "rb");
        if (!diskFile) { tlog(@"dump_err", @{@"e": @"fopen disk"}); return; }

        struct mach_header_64 hdr;
        fread(&hdr, sizeof(hdr), 1, diskFile);
        if (hdr.magic != MH_MAGIC_64) {
            fclose(diskFile);
            tlog(@"dump_err", @{@"e": @"bad magic", @"m": [NSString stringWithFormat:@"0x%x", hdr.magic]});
            return;
        }

        uint8_t *lcBuf = (uint8_t *)malloc(hdr.sizeofcmds);
        if (!lcBuf) { fclose(diskFile); tlog(@"dump_err", @{@"e": @"malloc lc"}); return; }
        fread(lcBuf, 1, hdr.sizeofcmds, diskFile);
        fclose(diskFile);

        tlog(@"dump_hdr", @{@"ncmds": @(hdr.ncmds), @"sizeofcmds": @(hdr.sizeofcmds)});

        // 计算输出大小
        uint64_t fileSize = sizeof(struct mach_header_64) + hdr.sizeofcmds;
        uint8_t *ptr = lcBuf;
        for (uint32_t i = 0; i < hdr.ncmds; i++) {
            struct load_command *lc = (struct load_command *)ptr;
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                uint64_t end = seg->fileoff + seg->filesize;
                if (end > fileSize) fileSize = end;
            }
            ptr += lc->cmdsize;
        }
        tlog(@"dump_plan", @{@"fileSize": @(fileSize)});

        uint8_t *buf = (uint8_t *)calloc(1, fileSize);
        if (!buf) { free(lcBuf); tlog(@"dump_err", @{@"e": @"calloc"}); return; }

        // 写磁盘 header
        memcpy(buf, &hdr, sizeof(hdr));
        memcpy(buf + sizeof(hdr), lcBuf, hdr.sizeofcmds);

        // 用 mach_vm_read_overwrite 绕过 XO 内存保护从内存读解密内容
        ptr = lcBuf;
        for (uint32_t i = 0; i < hdr.ncmds; i++) {
            struct load_command *lc = (struct load_command *)ptr;
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                if (seg->filesize > 0) {
                    vm_address_t src = (vm_address_t)seg->vmaddr + (vm_address_t)slide;
                    if (!vmread(src, buf + seg->fileoff, (vm_size_t)seg->filesize)) {
                        tlog(@"dump_vmread_fail", @{@"seg": @(seg->segname), @"src": [NSString stringWithFormat:@"0x%lx", (unsigned long)src]});
                    }
                }
            }
            if (lc->cmd == LC_ENCRYPTION_INFO_64) {
                uint64_t off = sizeof(struct mach_header_64) + ((uint8_t *)lc - lcBuf);
                struct encryption_info_command_64 *enc = (struct encryption_info_command_64 *)(buf + off);
                enc->cryptid = 0;
            }
            ptr += lc->cmdsize;
        }
        free(lcBuf);

        NSString *outPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"decrypted_qunar.bin"];
        FILE *outFile = fopen(outPath.UTF8String, "wb");
        if (!outFile) { free(buf); tlog(@"dump_err", @{@"e": @"fopen out"}); return; }
        size_t written = fwrite(buf, 1, (size_t)fileSize, outFile);
        fclose(outFile);
        free(buf);
        tlog(@"dump_ok", @{@"bytes": @(written), @"path": outPath});
    } @catch (NSException *ex) {
        tlog(@"dump_crash", @{@"e": ex.name, @"r": ex.reason ?: @"nil"});
    }
}
