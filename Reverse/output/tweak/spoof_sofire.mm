#import <Foundation/Foundation.h>
#include <mach-o/dyld.h>
#import <substrate.h>
#import "tlog.h"
#import "spoof_sofire.h"

static void *replaced_sofire_detect(void) { return NULL; }

extern "C" void installSofireHooks(void) {
    intptr_t slide = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *n = _dyld_get_image_name(i);
        if (n && strstr(n, "QunariPhone_Cook_CM")) {
            slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    if (!slide) {
        tlog(@"sofire_hook_spoof", @{@"err": @"slide_not_found"});
        return;
    }
    MSHookFunction((void *)(0x100000000ULL + (uintptr_t)slide + 0xE4CAE4ULL),
                   (void *)replaced_sofire_detect, NULL);
    tlog(@"sofire_hook_spoof", @{
        @"slide": [NSString stringWithFormat:@"%lx", (unsigned long)slide],
        @"addr":  [NSString stringWithFormat:@"%lx",
                   (unsigned long)(0x100000000ULL + slide + 0xE4CAE4ULL)]
    });
}
