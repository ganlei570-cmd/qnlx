#include "fishhook.h"
#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

static void perform_rebinding_with_section(struct rebinding rebindings[],
                                           size_t rebindings_nel,
                                           const mach_header_t *mh,
                                           intptr_t slide,
                                           section_t *la_symtab_section,
                                           section_t *nl_symtab_section,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab) {
    section_t *sections[] = { la_symtab_section, nl_symtab_section };
    for (int i = 0; i < 2; i++) {
        section_t *sect = sections[i];
        if (!sect) continue;
        uint32_t *indirect_symbol_indices = indirect_symtab + sect->reserved1;
        void **indirect_symbol_bindings = (void **)((uintptr_t)slide + sect->addr);
        for (uint j = 0; j < sect->size / sizeof(void *); j++) {
            uint32_t symtab_index = indirect_symbol_indices[j];
            if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
                symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS))
                continue;
            uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
            char *sym_name = strtab + strtab_offset;
            if (strtab_offset == 0) continue;
            char *sym = sym_name;
            if (sym[0] == '_') sym++;
            for (size_t k = 0; k < rebindings_nel; k++) {
                if (strcmp(sym, rebindings[k].name) == 0) {
                    if (rebindings[k].replaced && indirect_symbol_bindings[j] != rebindings[k].replacement)
                        *(rebindings[k].replaced) = indirect_symbol_bindings[j];
                    indirect_symbol_bindings[j] = rebindings[k].replacement;
                }
            }
        }
    }
}

static void rebind_symbols_for_image(struct rebinding rebindings[],
                                     size_t rebindings_nel,
                                     const struct mach_header *header,
                                     intptr_t slide) {
    segment_command_t *cur_seg_cmd;
    segment_command_t *linkedit_segment = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (segment_command_t *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            if (!strcmp(((segment_command_t *)cur_seg_cmd)->segname, SEG_LINKEDIT))
                linkedit_segment = cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur_seg_cmd;
        }
    }
    if (!linkedit_segment || !symtab_cmd || !dysymtab_cmd) return;

    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (segment_command_t *)cur;
        if (cur_seg_cmd->cmd != LC_SEGMENT_ARCH_DEPENDENT) continue;
        if (strcmp(((segment_command_t *)cur_seg_cmd)->segname, SEG_DATA) != 0 &&
            strcmp(((segment_command_t *)cur_seg_cmd)->segname, "__DATA_CONST") != 0) continue;
        section_t *la = NULL, *nl = NULL;
        for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
            section_t *sect = (section_t *)(cur + sizeof(segment_command_t)) + j;
            if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) la = sect;
            if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) nl = sect;
        }
        if (la || nl)
            perform_rebinding_with_section(rebindings, rebindings_nel,
                                           (mach_header_t *)header, slide,
                                           la, nl, symtab, strtab, indirect_symtab);
    }
}

static struct rebinding *_rebindings = NULL;
static size_t _rebindings_nel = 0;

static void _rebind_all_images(const struct mach_header *mh, intptr_t vmaddr_slide) {
    rebind_symbols_for_image(_rebindings, _rebindings_nel, mh, vmaddr_slide);
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
    struct rebinding *new_bindings = malloc(rebindings_nel * sizeof(struct rebinding));
    if (!new_bindings) return -1;
    memcpy(new_bindings, rebindings, rebindings_nel * sizeof(struct rebinding));
    if (_rebindings) free(_rebindings);
    _rebindings = new_bindings;
    _rebindings_nel = rebindings_nel;
    _dyld_register_func_for_add_image(_rebind_all_images);
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++)
        rebind_symbols_for_image(rebindings, rebindings_nel,
                                 _dyld_get_image_header(i),
                                 _dyld_get_image_vmaddr_slide(i));
    return 0;
}

int rebind_symbols_image(void *header, intptr_t slide,
                         struct rebinding rebindings[], size_t rebindings_nel) {
    rebind_symbols_for_image(rebindings, rebindings_nel, (const struct mach_header *)header, slide);
    return 0;
}
