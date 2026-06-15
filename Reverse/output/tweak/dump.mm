#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import "tlog.h"
#import "dump.h"

void dumpMainBinary(void) {
    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!hdr || hdr->magic != MH_MAGIC_64) {
        tlog(@"dump_err", @{@"e": @"not arm64 macho"});
        return;
    }

    intptr_t slide = _dyld_get_image_vmaddr_slide(0);

    // 计算输出文件大小（各 segment fileoff+filesize 的最大值）
    uint8_t *ptr = (uint8_t *)hdr + sizeof(struct mach_header_64);
    uint64_t fileSize = sizeof(struct mach_header_64) + hdr->sizeofcmds;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        struct load_command *lc = (struct load_command *)ptr;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            uint64_t end = seg->fileoff + seg->filesize;
            if (end > fileSize) fileSize = end;
        }
        ptr += lc->cmdsize;
    }

    uint8_t *buf = (uint8_t *)calloc(1, fileSize);
    if (!buf) {
        tlog(@"dump_err", @{@"e": @"calloc", @"sz": @(fileSize)});
        return;
    }

    // 复制 header + load commands
    memcpy(buf, hdr, sizeof(struct mach_header_64) + hdr->sizeofcmds);

    // 从内存里逐 segment 复制解密后的内容
    ptr = (uint8_t *)hdr + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        struct load_command *lc = (struct load_command *)ptr;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (seg->filesize > 0 && seg->vmsize > 0) {
                void *src = (void *)((uintptr_t)seg->vmaddr + (uintptr_t)slide);
                size_t copyLen = (size_t)MIN(seg->filesize, seg->vmsize);
                memcpy(buf + seg->fileoff, src, copyLen);
            }
        }
        // 清除 FairPlay 加密标记 → IDA 直接识别为未加密
        if (lc->cmd == LC_ENCRYPTION_INFO_64) {
            uint64_t lcOff = (uint8_t *)lc - (uint8_t *)hdr;
            struct encryption_info_command_64 *enc =
                (struct encryption_info_command_64 *)(buf + lcOff);
            enc->cryptid = 0;
        }
        ptr += lc->cmdsize;
    }

    NSString *dir = NSTemporaryDirectory();
    NSString *path = [dir stringByAppendingPathComponent:@"decrypted_qunar.bin"];
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
