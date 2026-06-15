#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import "tlog.h"
#import "dump.h"

void dumpMainBinary(void) {
    // 按名字找主二进制（index 0 在 ElleKit 注入环境下不一定是主程序）
    uint32_t imgCount = _dyld_image_count();
    int32_t mainIdx = -1;
    for (uint32_t i = 0; i < imgCount; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "QunariPhone_Cook_CM") && !strstr(name, ".dylib") && !strstr(name, ".framework")) {
            mainIdx = (int32_t)i;
            tlog(@"dump_found", @{@"idx": @(i), @"name": @(name)});
            break;
        }
    }
    if (mainIdx < 0) {
        tlog(@"dump_err", @{@"e": @"main binary not found in dyld images"});
        return;
    }

    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)_dyld_get_image_header((uint32_t)mainIdx);
    if (!hdr || hdr->magic != MH_MAGIC_64) {
        tlog(@"dump_err", @{@"e": @"not arm64 macho"});
        return;
    }
    intptr_t slide = _dyld_get_image_vmaddr_slide((uint32_t)mainIdx);

    // 遍历 segments 计算文件大小 & 记录最大 segment 供诊断
    uint8_t *ptr = (uint8_t *)hdr + sizeof(struct mach_header_64);
    uint64_t fileSize = sizeof(struct mach_header_64) + hdr->sizeofcmds;
    uint64_t maxSegFilesize = 0;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        struct load_command *lc = (struct load_command *)ptr;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            uint64_t end = seg->fileoff + seg->filesize;
            if (end > fileSize) fileSize = end;
            if (seg->filesize > maxSegFilesize) maxSegFilesize = seg->filesize;
        }
        ptr += lc->cmdsize;
    }
    tlog(@"dump_plan", @{@"fileSize": @(fileSize), @"maxSeg": @(maxSegFilesize), @"ncmds": @(hdr->ncmds)});

    uint8_t *buf = (uint8_t *)calloc(1, fileSize);
    if (!buf) {
        tlog(@"dump_err", @{@"e": @"calloc", @"sz": @(fileSize)});
        return;
    }

    memcpy(buf, hdr, sizeof(struct mach_header_64) + hdr->sizeofcmds);

    ptr = (uint8_t *)hdr + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        struct load_command *lc = (struct load_command *)ptr;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (seg->filesize > 0) {
                void *src = (void *)((uintptr_t)seg->vmaddr + (uintptr_t)slide);
                memcpy(buf + seg->fileoff, src, (size_t)seg->filesize);
            }
        }
        if (lc->cmd == LC_ENCRYPTION_INFO_64) {
            uint64_t off = (uint8_t *)lc - (uint8_t *)hdr;
            struct encryption_info_command_64 *enc =
                (struct encryption_info_command_64 *)(buf + off);
            enc->cryptid = 0;
        }
        ptr += lc->cmdsize;
    }

    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"decrypted_qunar.bin"];
    FILE *f = fopen(path.UTF8String, "wb");
    if (!f) {
        free(buf);
        tlog(@"dump_err", @{@"e": @"fopen", @"p": path});
        return;
    }
    size_t written = fwrite(buf, 1, (size_t)fileSize, f);
    fclose(f);
    free(buf);
    tlog(@"dump_ok", @{@"bytes": @(written), @"path": path});
}
