import collections
import csv

VALID = 'VALID'
EMPTY_PDPE = 'EMPTY_PDPE'
EMPTY_PTE = 'EMPTY_PTE'
EMPTY_PML4E = 'EMPTY_PML4E'
PAGEFILE = 'PAGEFILE'
LARGE = 'LARGE'
DEMAND_ZERO = 'DEMAND_ZERO'
UNKNOWN = 'UNKNOWN'

PROTO_VALID = 'PROTO_VALID'
PROTO_UNKNOWN = 'PROTO_UNKNOWN'
PROTO_INVALID = 'PROTO_INVALID'
PF_PROTOTYPE = 'PF_PROTOTYPE'
DZ_PROTOTYPE = 'DZ_PROTOTYPE'

MAPPED_FILE = 'MAPPED_FILE'
MAPPED_FILE_PROTO = 'MAPPED_FILE_PROTO'
MAPPED_FILE_UNKNOWN = 'MAPPED_FILE_UNKNOWN'

WRITEABLE = 'WRITEABLE'
KERNEL_MODE = 'KERNEL_MODE'
CACHE_WRITEBACK = 'CACHE_WRITEBACK'
CACHE = 'CACHE'
ACCESSED = 'ACCESSED'
DIRTY = 'DIRTY'
COPYONWRITE = 'COPYONWRITE'

GLOBAL_PDE = 'GLOBAL_PDE'
NX = 'NX'

profiling = collections.defaultdict(lambda: collections.defaultdict(int))
file_objects = collections.defaultdict(set)

def write_file(outfilename):

    profiler_file = open(outfilename + '.csv', 'w')
    csv_writer = csv.writer(profiler_file, delimiter=';')
    csv_writer.writerow(['Process', 'VALID', 'EMPTY_PDPE', 'EMPTY_PML4E', 'EMPTY_PTE', 'PAGEFILE', 'LARGE', 'DEMAND_ZERO', 'UNKNOWN',
                         'PROTO_VALID', 'PROTO_UNKNOWN', 'PROTO_INVALID', 'PF_PROTOTYPE', 'DZ_PROTOTYPE', 'MAPPED_FILE',
                         'MAPPED_FILE_PROTO', 'MAPPED_FILE_UNKNOWN', 'FILE_OBJECTS', 'WRITEABLE', 'KERNEL_MODE',
                         'CACHE_WRITEBACK', 'CACHE', 'ACCESSED', 'DIRTY', 'COPYONWRITE', 'GLOBAL_PDE', 'NX'])
    for as_name in profiling.keys():
        row = []
        row.append(as_name)
        row.append(profiling[as_name][VALID]) if VALID in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][EMPTY_PDPE]) if EMPTY_PDPE in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][EMPTY_PML4E]) if EMPTY_PML4E in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][EMPTY_PTE]) if EMPTY_PTE in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][PAGEFILE]) if PAGEFILE in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][LARGE]) if LARGE in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][DEMAND_ZERO]) if DEMAND_ZERO in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][UNKNOWN]) if UNKNOWN in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][PROTO_VALID]) if PROTO_VALID in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][PROTO_UNKNOWN]) if PROTO_UNKNOWN in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][PROTO_INVALID]) if PROTO_INVALID in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][PF_PROTOTYPE]) if PF_PROTOTYPE in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][DZ_PROTOTYPE]) if DZ_PROTOTYPE in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][MAPPED_FILE]) if MAPPED_FILE in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][MAPPED_FILE_PROTO]) if MAPPED_FILE_PROTO in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][MAPPED_FILE_UNKNOWN]) if MAPPED_FILE_UNKNOWN in profiling[as_name].keys() else row.append(0)
        row.append(str(file_objects[as_name])) if as_name in file_objects.keys() else row.append(0)
        row.append(profiling[as_name][WRITEABLE]) if WRITEABLE in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][KERNEL_MODE]) if KERNEL_MODE in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][CACHE_WRITEBACK]) if CACHE_WRITEBACK in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][CACHE]) if CACHE in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][ACCESSED]) if ACCESSED in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][DIRTY]) if DIRTY in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][COPYONWRITE]) if COPYONWRITE in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][GLOBAL_PDE]) if GLOBAL_PDE in profiling[as_name].keys() else row.append(0)
        row.append(profiling[as_name][NX]) if NX in profiling[as_name].keys() else row.append(0)

        csv_writer.writerow(row)
    profiler_file.close()
