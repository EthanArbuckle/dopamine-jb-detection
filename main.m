//
//  main.m
//  dopamine-detect
//
//  Created by Ethan Arbuckle on 5/30/23.
//

#include <Foundation/Foundation.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <dlfcn.h>


int is_device_jailbroken_with_dopamine(void) {
    
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;

    uint64_t slide = 0;
    struct symtab_command *symcmd = NULL;
    struct segment_command_64 *linkedit_cmd = NULL;
    struct nlist_64 *symtab = NULL;
    const char *strtab = NULL;
    
    struct load_command *lc = (struct load_command *)((mach_vm_address_t)infos->dyldImageLoadAddress + sizeof(struct mach_header_64));
    for (int command = 0; command < infos->dyldImageLoadAddress->ncmds; command++) {
        switch (lc->cmd) {
            case LC_SYMTAB:
                symcmd = (struct symtab_command *)lc;
                break;
                
            case LC_SEGMENT_64: {
                struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                if (seg->fileoff == 0) {
                    slide = (intptr_t)infos->dyldImageLoadAddress - seg->vmaddr;
                }
                
                if (strcmp(seg->segname, SEG_LINKEDIT) == 0) {
                    linkedit_cmd = (struct segment_command_64 *)seg;
                    break;
                }
                break;
            }
                
            default:
                break;
        }
        
        lc = (struct load_command *)((mach_vm_address_t)lc + lc->cmdsize);
    }
    
    if (linkedit_cmd == NULL || symcmd == NULL) {
        return 0;
    }
    
    symtab = (void *)linkedit_cmd->vmaddr + symcmd->symoff - linkedit_cmd->fileoff + slide;
    strtab = (void *)linkedit_cmd->vmaddr + symcmd->stroff - linkedit_cmd->fileoff + slide;
    
    void *_dyld_getAmfi = NULL;
    for (uint32_t i = 0; i < symcmd->nsyms; i++) {
        
        struct nlist_64 *sym = &symtab[i];
        if ((sym->n_type & N_TYPE) != N_SECT) {
            continue;
        }
        
        uint32_t strx = sym->n_un.n_strx;
        const char *name = strx == 0 ? "" : strtab + strx;
        if (strcmp(name, "__ZN5dyld413ProcessConfig8Security7getAMFIERKNS0_7ProcessERNS_15SyscallDelegateE") == 0) {
            _dyld_getAmfi = (void *)sym->n_value + slide;
            break;
        }
    }
    
    if (_dyld_getAmfi == NULL) {
        return 0;
    }
    
    Dl_info info;
    if (dladdr(_dyld_getAmfi, &info) != 0) {
        return 0;
    }
    
    FILE *fd = fopen(infos->dyldPath, "rb");
    fseek(fd, (intptr_t)_dyld_getAmfi - (intptr_t)info.dli_fbase, SEEK_SET);
    
    uint32_t buffer[2];
    size_t bytesRead = fread(buffer, sizeof(uint32_t), 2, fd);
    fclose(fd);
    
    if (bytesRead != 2) {
        return 0;
    }
    
    return buffer[0] == 0xD2801BE0 && buffer[1] == 0xD65F03C0;
}


int main(int argc, char * argv[]) {

    
    NSLog(@"is_device_jailbroken_with_dopamine: %d", is_device_jailbroken_with_dopamine());

    return 0;
}
