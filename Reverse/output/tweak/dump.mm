#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import "tlog.h"
#import "dump.h"

static bool vmread_at(vm_address_t src, void *dst, vm_size_t size) {
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

        // Use actual in-memory base from dyld — avoids slide calculation issues
        const struct mach_header_64 *inMemHdr =
            (const struct mach_header_64 *)_dyld_get_image_header((uint32_t)mainIdx);
        vm_address_t inMemBase = (vm_address_t)inMemHdr;
        const char *binaryPath = _dyld_get_image_name((uint32_t)mainIdx);

        tlog(@"dump_start", @{@"base": [NSString stringWithFormat:@"0x%lx", (unsigned long)inMemBase],
                               @"path": @(binaryPath)});

        if (inMemHdr->magic != MH_MAGIC_64) {
            tlog(@"dump_err", @{@"e": @"bad magic", @"m": [NSString stringWithFormat:@"0x%x", inMemHdr->magic]});
            return;
        }

        uint8_t *lcBuf = (uint8_t *)malloc(inMemHdr->sizeofcmds);
        if (!lcBuf) { tlog(@"dump_err", @{@"e": @"malloc lc"}); return; }

        // Read load commands from disk (unencrypted header area)
        FILE *diskFile = fopen(binaryPath, "rb");
        if (!diskFile) { free(lcBuf); tlog(@"dump_err", @{@"e": @"fopen disk"}); return; }
        fseek(diskFile, sizeof(struct mach_header_64), SEEK_SET);
        fread(lcBuf, 1, inMemHdr->sizeofcmds, diskFile);
        fclose(diskFile);

        tlog(@"dump_hdr", @{@"ncmds": @(inMemHdr->ncmds), @"sizeofcmds": @(inMemHdr->sizeofcmds)});

        // Calculate output file size
        uint64_t fileSize = sizeof(struct mach_header_64) + inMemHdr->sizeofcmds;
        uint8_t *ptr = lcBuf;
        for (uint32_t i = 0; i < inMemHdr->ncmds; i++) {
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

        // Write in-memory header
        memcpy(buf, inMemHdr, sizeof(struct mach_header_64));
        memcpy(buf + sizeof(struct mach_header_64), lcBuf, inMemHdr->sizeofcmds);

        // Read each segment: address = inMemBase + fileoff (valid for arm64 PIE binaries)
        ptr = lcBuf;
        for (uint32_t i = 0; i < inMemHdr->ncmds; i++) {
            struct load_command *lc = (struct load_command *)ptr;
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                if (seg->filesize > 0) {
                    vm_address_t src = inMemBase + seg->fileoff;
                    if (!vmread_at(src, buf + seg->fileoff, (vm_size_t)seg->filesize)) {
                        tlog(@"dump_vmread_fail", @{@"seg": @(seg->segname),
                              @"src": [NSString stringWithFormat:@"0x%lx", (unsigned long)src]});
                    }
                }
            }
            if (lc->cmd == LC_ENCRYPTION_INFO_64) {
                uint64_t off = sizeof(struct mach_header_64) + ((uint8_t *)lc - lcBuf);
                struct encryption_info_command_64 *enc =
                    (struct encryption_info_command_64 *)(buf + off);
                enc->cryptid = 0;
            }
            ptr += lc->cmdsize;
        }
        free(lcBuf);

        // Log first 4 bytes to verify magic
        tlog(@"dump_magic_check", @{@"b": [NSString stringWithFormat:@"0x%02x%02x%02x%02x",
              buf[0], buf[1], buf[2], buf[3]]});

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
