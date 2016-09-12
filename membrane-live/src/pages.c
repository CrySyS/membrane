#define PTRS_PER_PAE_PTE 512
#define PTRS_PER_PAE_PGD 512
#define PTRS_PER_PDE 1024

#define ENTRY_SIZE 8

#include <time.h>
#include "pages.h"
#include <stdio.h>
#include <stdlib.h>

int entry_prototype(uint64_t entry) {
    if(entry) {
        if((entry & (1 << 10)) && !(entry & (1 << 11))) {
            return 1;
        }
    }
    return 0;
}
    
int entry_present(uint64_t entry) {
    if(entry) {
        if(entry & 1) {
            return 1;
        }
        if((entry & (1 << 11)) && !(entry & (1 << 10))) {
            return 1;
        }
    }
    return 0;
}

int entry_transition(uint64_t entry) {
    if(entry) {
        if((entry & (1 << 11)) && !(entry & (1 << 10))) {
            return 1;
        }
    }
    return 0;
}

int entry_pagefile(uint64_t entry) {
    if(entry) {
        if(!(entry & (1 << 10)) && !(entry & (1 << 10))) {
            return 1;
        }
    }
    return 0;
}

int entry_subsection(uint64_t pte) {
    uint64_t subsection_addr = (pte & 0xffffffff00000000) >> 32;
    if(subsection_addr == 0) {
        return 0;
    }
    // _MMPTE_SUBSECTION unused null tests
    if (((pte >> 1) & 0b1111) != 0) {
        //print "unused0 test failed"
        return 0;
    }
    if (((pte >> 11) & 0x1FFFFF) != 0) {
        //print "unused1 test failed"
        return 0;
    }
    return 1;
}

int page_size_flag(uint64_t entry) {
    if((entry & (1 << 7)) == (1 << 7)) {
        return 1;
    }
    return 0;
}

uint64_t get_pml4e(vmi_instance_t vmi, uint64_t cr3, uint64_t vaddr) {
    uint64_t pml4e_paddr = (cr3 & 0xffffffffff000) | ((vaddr & 0xff8000000000) >> 36);
    uint64_t pml4e;
    vmi_read_64_pa(vmi, pml4e_paddr, &pml4e);
    return pml4e;
}

uint64_t get_pdpte(vmi_instance_t vmi, uint64_t pml4e, uint64_t vaddr) {
    uint64_t pdpte_addr = (pml4e & 0xffffffffff000) | ((vaddr & 0x7FC0000000) >> 27);
    uint64_t pdpte;
    vmi_read_64_pa(vmi, pdpte_addr, &pdpte);
    return pdpte;
}

uint64_t get_pde(vmi_instance_t vmi, uint64_t pdpte, uint64_t vaddr) {
    uint64_t pde_addr = (pdpte & 0xffffffffff000) | ((vaddr & 0x3fe00000) >> 18);
    uint64_t pde;
    vmi_read_64_pa(vmi, pde_addr, &pde);
    return pde;
}

FILE * init_profiler(char * pid) {
    trigger_profiler = 0;
    pid_filter = atoi(pid);

    time_t rawtime;
    struct tm * timeinfo;

    time ( &rawtime );
    timeinfo = localtime ( &rawtime );

    char time_buffer[80];
    strftime(time_buffer,80,"%Y%m%d%H%M%S",timeinfo);

    char name_buffer[255];
    snprintf(name_buffer, 254, "/root/profiler/profiler_%s.csv", time_buffer);
    FILE * fd1 = fopen(name_buffer, "a+");
    fprintf(fd1, "PID;");
    fprintf(fd1, "ProcName;");
    fprintf(fd1, "FnName;");
    fprintf(fd1, "Param1;");
    fprintf(fd1, "Param2;");
    fprintf(fd1, "Param3;");
    fprintf(fd1, "INVALID_PML4E;");
    fprintf(fd1, "INVALID_PDPE;");
    fprintf(fd1, "INVALID_PDE;");
    fprintf(fd1, "VALID_PTE;");
    fprintf(fd1, "LARGE_PDPE;");
    fprintf(fd1, "LARGE_PDE;");
    fprintf(fd1, "GLOBAL_PTE;");
    fprintf(fd1, "WRITEABLE;");
    fprintf(fd1, "KERNEL_MODE;");
    fprintf(fd1, "CACHE_WRITEBACK;");
    fprintf(fd1, "CACHE;");
    fprintf(fd1, "ACCESSED;");
    fprintf(fd1, "DIRTY;");
    fprintf(fd1, "COPYONWRITE;");
    fprintf(fd1, "DZ_PROTOTYPE;");
    fprintf(fd1, "DEMAND_ZERO;");
    fprintf(fd1, "PF_PROTOTYPE;");
    fprintf(fd1, "PAGEFILE;");
    fprintf(fd1, "PROTO_TRANSITION;");
    fprintf(fd1, "PROTO_VALID;");
    fprintf(fd1, "MAPPED_FILE;");
    fprintf(fd1, "tMAPPED_FILE_PROTO;");
    fprintf(fd1, "PROTO_UNKNOWN;");
    fprintf(fd1, "TRANSITION;");
    fprintf(fd1, "PROTOTYPE_VAD;");
    fprintf(fd1, "UNKNOWN;");
    fprintf(fd1, "EMPTY_PTE;");
    fprintf(fd1, "MODIFIED_NOWRITE;");
    fprintf(fd1, "PROTO_MODIFIED_NOWRITE\n");
    fflush(fd1);
    return fd1;
}

void dump_profile(Statistic * stat, vmi_pid_t pid, FnParams * fn_data) { 
    if(fd_profiler == 0) {
        printf("Uninitialized profiler..");
    }
    fprintf(fd_profiler, "%d;", pid);
    fprintf(fd_profiler, "%s;", fn_data->proc_name);
    fprintf(fd_profiler, "%s;", fn_data->fn_name);
    fprintf(fd_profiler, "%x;", fn_data->param1);
    fprintf(fd_profiler, "%x;", fn_data->param2);
    fprintf(fd_profiler, "%x;", fn_data->param3);
    fprintf(fd_profiler, "%d;", stat->INVALID_PML4E);
    fprintf(fd_profiler, "%d;", stat->INVALID_PDPE);
    fprintf(fd_profiler, "%d;", stat->INVALID_PDE);
    fprintf(fd_profiler, "%d;", stat->LARGE_PDPE);
    fprintf(fd_profiler, "%d;", stat->LARGE_PDE);
    fprintf(fd_profiler, "%d;", stat->VALID_PTE);
    fprintf(fd_profiler, "%d;", stat->GLOBAL_PTE);
    fprintf(fd_profiler, "%d;", stat->WRITEABLE);
    fprintf(fd_profiler, "%d;", stat->KERNEL_MODE);
    fprintf(fd_profiler, "%d;", stat->CACHE_WRITEBACK);
    fprintf(fd_profiler, "%d;", stat->CACHE);
    fprintf(fd_profiler, "%d;", stat->ACCESSED);
    fprintf(fd_profiler, "%d;", stat->DIRTY);
    fprintf(fd_profiler, "%d;", stat->COPYONWRITE);
    fprintf(fd_profiler, "%d;", stat->DZ_PROTOTYPE);
    fprintf(fd_profiler, "%d;", stat->DEMAND_ZERO);
    fprintf(fd_profiler, "%d;", stat->PF_PROTOTYPE);
    fprintf(fd_profiler, "%d;", stat->PAGEFILE);
    fprintf(fd_profiler, "%d;", stat->PROTO_TRANSITION);
    fprintf(fd_profiler, "%d;", stat->PROTO_VALID);
    fprintf(fd_profiler, "%d;", stat->MAPPED_FILE);
    fprintf(fd_profiler, "%d;", stat->MAPPED_FILE_PROTO);
    fprintf(fd_profiler, "%d;", stat->PROTO_UNKNOWN);
    fprintf(fd_profiler, "%d;", stat->TRANSITION);
    fprintf(fd_profiler, "%d;", stat->PROTOTYPE_VAD);
    fprintf(fd_profiler, "%d;", stat->UNKNOWN);
    fprintf(fd_profiler, "%d;", stat->EMPTY_PTE);
    fprintf(fd_profiler, "%d;", stat->MODIFIED_NOWRITE);
    fprintf(fd_profiler, "%d\n", stat->PROTO_MODIFIED_NOWRITE);
    fflush(fd_profiler);
}

void profile_pte_flags(Statistic * stat, uint64_t pxx) {
    int writeable = (pxx & 0x2) == 0x2;
    int kernel_mode = (pxx & 0x4) == 0;
    int cache_writeback = (pxx & 0x8) == 0;
    int cache = (pxx & 0x10) == 0;
    int accessed = (pxx & 0x20) == 0x20;
    int dirty = (pxx & 0x40) == 0x40;
    int copyonwrite = (pxx & 0x200) == 0x200;
    int global = (pxx & 0x100) != 0;
    
    if(global) stat->GLOBAL_PTE++;
    if(writeable) stat->WRITEABLE++;
    if(kernel_mode) stat->KERNEL_MODE++;
    if(cache_writeback) stat->CACHE_WRITEBACK++;
    if(cache) stat->CACHE++;
    if(accessed) stat->ACCESSED++;
    if(dirty) stat->DIRTY++;
    if(copyonwrite) stat->COPYONWRITE++;
}

void pagefilePTE(Statistic * stat, uint64_t vaddr, uint64_t pte_value, int is_proto) {
    uint64_t pagefile_num = (pte_value >> 1) & 0xf;
    uint64_t pagefile_offset = (pte_value & 0xfffff000) + (vaddr & 0xfff);
    // TODO: check validation
    if (pagefile_offset == 0 /* && pagefile_num == 0*/) {
        if(is_proto) {
            stat->DZ_PROTOTYPE++;
        }
        else {
            stat->DEMAND_ZERO++;
        }
    }
    else {
        if(is_proto) {
            stat->PF_PROTOTYPE++;
        }
        else {
            stat->PAGEFILE++;
        }
    }
}

void prototypePTE(Statistic * stat, uint64_t vaddr, uint64_t ppte_value) {
    profile_pte_flags(stat, ppte_value);
    if(entry_present(ppte_value)) {
        if(entry_transition(ppte_value)) {
            // TODO: entry_dirty
            if ((ppte_value & 0x40) == 0x40) {
                stat->PROTO_MODIFIED_NOWRITE++;
            }
            else {
                stat->PROTO_TRANSITION++;
            }
        }
        else {
            stat->PROTO_VALID++;
        }
    }
    else if(entry_prototype(ppte_value)) {
        if(entry_subsection(ppte_value)) {
            stat->MAPPED_FILE_PROTO++;
        }
        else {
            stat->PROTO_UNKNOWN++;
        }
    }
    else if(entry_pagefile(ppte_value)) {
        pagefilePTE(stat, vaddr, ppte_value, 1);
    }
    else {
        stat->PROTO_UNKNOWN++;
    }
}

void PTE(vmi_instance_t vmi, Statistic * stat, vmi_pid_t current_pid, uint64_t vaddr, int64_t pte_value) {    
    profile_pte_flags(stat, pte_value);
    if (entry_present(pte_value)) {
        if(entry_transition(pte_value)) {
            // TODO: entry_dirty
            if ((pte_value & 0x40) == 0x40) {
                stat->MODIFIED_NOWRITE++;
            }
            else {
                stat->TRANSITION++;
            }
        }
        else {
            stat->VALID_PTE++;
        }
    }
    else if(entry_prototype(pte_value)) {
        if(entry_subsection(pte_value)) {
            stat->MAPPED_FILE++;
        }
        else {
            uint64_t ppte_vaddr = (pte_value & 0xffffffff00000000) >> 32;
            uint64_t ppte_value;
            vmi_read_64_va(vmi, ppte_vaddr, current_pid, &ppte_value);
            if (0xffffffff00000000 == (0xffffffff00000000 & pte_value)) {
                stat->PROTOTYPE_VAD++;
            }
            else {
                prototypePTE(stat, vaddr, ppte_value);
            }
        }
    }
    else if(entry_pagefile(pte_value)) {
        pagefilePTE(stat, vaddr, pte_value, 0);
    }
    else {
        stat->UNKNOWN++;
    }
    
}

void get_pages(vmi_instance_t vmi, reg_t cr3, FnParams * fn_data) {
    Statistic stat = {0};

    // filter pid to optimize
    if (pid_filter != -1) {
        if (current_pid != pid_filter) return;
    }
    
    uint64_t cr3_c = (uint64_t)cr3;
//    fprintf(fd1, "CR3: %x\n", cr3_c);
    
    for(uint64_t pml4e = 0; pml4e < 0x200; pml4e++) {
        uint64_t vaddr = pml4e << 39;
        
        uint64_t pml4e_value = get_pml4e(vmi, cr3_c, vaddr);

        if (!entry_present(pml4e_value) && (pml4e_value != 0)) {
            stat.INVALID_PML4E++;
            continue;
        }
        
//      fprintf(fd1, "\tpml4e: %x\n", pml4e_value);
        for(uint64_t pdpte = 0; pdpte < 0x200; pdpte++) {
            vaddr = vaddr | (pdpte << 30);
            uint64_t pdpte_value = get_pdpte(vmi, pml4e_value, vaddr);
            if (!entry_present(pdpte_value) && (pdpte_value != 0)) {
                stat.INVALID_PDPE++;
                continue;
            }
            
            if(page_size_flag(pdpte_value)) {
                stat.LARGE_PDPE++;
                continue;
            }
            
//          fprintf(fd1, "\tpdpte: %x\n", pdpte_value);
            for(uint64_t pde = 0; pde < 0x200; pde++) {
                vaddr = vaddr | (pde << 21);
                
                uint64_t pde_value = get_pde(vmi, pdpte_value, vaddr);
                if (!entry_present(pde_value) && (pde_value != 0)) {
                    stat.INVALID_PDE++;
                    continue;
                }
                
                /*if (pde_value & 0x100) {
                    stat.GLOBAL_PDE++;
                }*/
                
                if(page_size_flag(pde_value)) {
                    stat.LARGE_PDE++;
                    continue;
                }
                
                uint64_t pte_table_addr = ((pde_value & 0xffffffffff000) | ((vaddr & 0x1ff000) >> 9));
                uint64_t data[0x200]; 
                vmi_read_pa(vmi, pte_table_addr, (void*)&data, 8 * 0x200);
                for(int i = 0; i < 0x200; i++) {
                    uint64_t pte_value = data[i];
                    if (pte_value == 0) {
                        stat.EMPTY_PTE++;
                        continue;
                    }
                    PTE(vmi, &stat, current_pid, vaddr, pte_value);
                }
            }
        }
    }
    
    dump_profile(&stat, current_pid, fn_data);
}

