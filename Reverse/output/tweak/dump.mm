#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import "tlog.h"
#import "dump.h"

// 从磁盘读正确 header（内存 header 被 FairPlay/Dopamine 修改过不可信），
// 用 vmaddr+slide 读内存中已解密的内容，合并写出完整 Mach-O。
void dumpMainBinary(void) {
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
    if (mainIdx < 0) { tlog(@"dump_err", @{@"e": @"binary not found"}); return; }

    intptr_t slide = _dyld_get_image_vmaddr_slide((uint32_t)mainIdx);
    const char *binaryPath = _dyld_get_image_name((uint32_t)mainIdx);
    tlog(@"dump_start", @{@"slide": [NSString stringWithFormat:@"0x%lx", (unsigned long)slide],
                           @"path": @(binaryPath)});

    // 从磁盘读 header（header 不在 FairPlay 加密范围内）
    FILE *diskFile = fopen(binaryPath, "rb");
    if (!diskFile) { tlog(@"dump_err", @{@"e": @"fopen disk failed"}); return; }

    struct mach_header_64 hdr;
    fread(&hdr, sizeof(hdr), 1, diskFile);
    if (hdr.magic != MH_MAGIC_64) {
        fclose(diskFile);
        tlog(@"dump_err", @{@"e": @"not thin arm64", @"magic": [NSString stringWithFormat:@"0x%x", hdr.magic]});
        return;
    }

    uint8_t *lcBuf = (uint8_t *)malloc(hdr.sizeofcmds);
    if (!lcBuf) { fclose(diskFile); tlog(@"dump_err", @{@"e": @"malloc lc"}); return; }
    fread(lcBuf, 1, hdr.sizeofcmds, diskFile);
    fclose(diskFile);

    tlog(@"dump_hdr", @{@"ncmds": @(hdr.ncmds), @"sizeofcmds": @(hdr.sizeofcmds)});

    // 计算输出文件总大小
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

    // 写磁盘 header（正确的 ncmds 和 load commands）
    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf + sizeof(hdr), lcBuf, hdr.sizeofcmds);

    // 从内存读各 segment 的解密内容
    ptr = lcBuf;
    for (uint32_t i = 0; i < hdr.ncmds; i++) {
        struct load_command *lc = (struct load_command *)ptr;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (seg->filesize > 0) {
                uintptr_t memAddr = (uintptr_t)seg->vmaddr + (uintptr_t)slide;
                memcpy(buf + seg->fileoff, (void *)memAddr, (size_t)seg->filesize);
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
}
