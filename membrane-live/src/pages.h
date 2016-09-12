#ifndef PAGES_H
#define PAGES_H

#include "structures.h"

typedef struct {
  int INVALID_PML4E;
  int INVALID_PDPE;
  int INVALID_PDE;
  int VALID_PTE;
  int LARGE_PDPE;
  int LARGE_PDE;
  int GLOBAL_PTE;
  int WRITEABLE;
  int KERNEL_MODE;
  int CACHE_WRITEBACK;
  int CACHE;
  int ACCESSED;
  int DIRTY;
  int COPYONWRITE;
  int DZ_PROTOTYPE;
  int DEMAND_ZERO;
  int PF_PROTOTYPE;
  int PAGEFILE;
  int PROTO_TRANSITION;
  int PROTO_VALID;
  int MAPPED_FILE;
  int MAPPED_FILE_PROTO;
  int PROTO_UNKNOWN;
  int TRANSITION;
  int PROTOTYPE_VAD;
  int UNKNOWN;
  int EMPTY_PTE;
  int MODIFIED_NOWRITE;
  int PROTO_MODIFIED_NOWRITE;
} Statistic;

typedef struct {
    char * proc_name;
    char * fn_name;
    reg_t param1;
    reg_t param2;
    reg_t param3;
} FnParams;

uint32_t trigger_profiler;
uint32_t pid_filter;
FILE * fd_profiler;

FILE * init_profiler(char * pid);
void get_pages(vmi_instance_t vmi, reg_t cr3, FnParams * fn_data);

#endif

