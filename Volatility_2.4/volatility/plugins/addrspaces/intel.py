# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2004,2005,2006 4tphi Research
#
# Authors:
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import struct
import sys
from volatility import debug
import volatility.plugins.addrspaces.paged as paged
import volatility.plugins.addrspaces.page_profiler as pprofiler
import volatility.obj as obj

entry_size = 8
pointer_size = 4
page_shift = 12
ptrs_per_pte = 1024
ptrs_per_pgd = 1024
ptrs_per_pae_pte = 512
ptrs_per_pae_pgd = 512
ptrs_per_pdpi = 4
pgdir_shift = 22
pdpi_shift = 30
pdptb_shift = 5
pde_shift = 21
ptrs_per_pde = 512
ptrs_page = 2048

class IA32PagedMemory(paged.AbstractWritablePagedMemory):
    """ Standard IA-32 paging address space.

    This class implements the IA-32 paging address space. It is responsible
    for translating each virtual (linear) address to a physical address.
    This is accomplished using hierachical paging structures.
    Every paging structure is 4096 bytes and is composed of entries.
    Each entry is 32 bits.  The first paging structure is located at the
    physical address found in CR3 (dtb).

    Additional Resources:
     - Intel(R) 64 and IA-32 Architectures Software Developer's Manual
       Volume 3A: System Programming Guide. Section 4.3
       http://www.intel.com/products/processor/manuals/index.htm
     - AMD64 Architecture Programmer's Manual Volume 2: System Programming
       http://support.amd.com/us/Processor_TechDocs/24593_APM_v2.pdf
     - N. Petroni, A. Walters, T. Fraser, and W. Arbaugh, "FATKit: A Framework
       for the Extraction and Analysis of Digital Forensic Data from Volatile
       System Memory" ,Digital Investigation Journal 3(4):197-210, December 2006.
       (submitted February 2006)
     - N. P. Maclean, "Acquisition and Analysis of Windows Memory,"
       University of Strathclyde, Glasgow, April 2006.
     - Russinovich, M., & Solomon, D., & Ionescu, A.
       "Windows Internals, 5th Edition", Microsoft Press, 2009.
    """
    order = 70
    pae = False
    paging_address_space = True
    checkname = 'IA32ValidAS'
    # Hardcoded page info to avoid expensive recalculation
    minimum_size = 0x1000
    alignment_gcd = 0x1000

    def __init__(self, base, config, dtb = 0, skip_as_check = False, *args, **kwargs):
        ## We must be stacked on someone else:
        self.as_assert(base, "No base Address Space")

        paged.AbstractWritablePagedMemory.__init__(self, base, config, dtb = dtb, skip_as_check = skip_as_check, *args, **kwargs)

    def is_valid_profile(self, profile):
        if profile.metadata.get('os', 'Unknown').lower() == 'windows':
            self.use_prototype_ptes = True

        return profile.metadata.get('memory_model', '32bit') == '32bit' or profile.metadata.get('os', 'Unknown').lower() == 'mac'

    def entry_pagefile(self, entry):
        if entry:
            if not (entry & (1 << 10)) and not (entry & (1 << 11)):
                return True

        return False

    def entry_prototype(self, entry):
        '''
        Return True if the PTE value is a pointer to a Prototype PTE.
        #4c0=10011000000
        That is, the Prototype flag (bit 10) is set
        and the Transition flag (bit 11) is not.
        '''
        if entry:
            if (entry & (1 << 10)) and not (entry & (1 << 11)):
                return True

        return False

    def entry_present(self, entry):
        if entry:
            if (entry & 1):
                return True

            # The page is in transition and not a prototype.
            # Thus, we will treat it as present.
            if (entry & (1 << 11)) and not (entry & (1 << 10)):
                return True

        return False

    def entry_subsection(self, pte):
        subsection_addr = (pte & 0xffffffff00000000) >> 32
        if subsection_addr == 0:
            return False
        subsection = obj.Object("_SUBSECTION", subsection_addr, self)
        if subsection == None:
            return False
        control_area = obj.Object("_CONTROL_AREA", subsection.ControlArea.v(), self)
        if control_area == None:
            return False
        file_object = control_area.FilePointer.dereference_as("_FILE_OBJECT")
        if file_object == None:
            return False
        FileName = str(file_object.FileName)
        if FileName == '':
            return False
        # _MMPTE_SUBSECTION unused null tests
        if ((pte >> 1) & 0b1111) != 0:
            #print "unused0 test failed"
            return False
        if ((pte >> 11) & 0x1FFFFF) != 0:
            #print "unused1 test failed"
            return False
        return True

    def page_size_flag(self, entry):
        if (entry & (1 << 7)) == (1 << 7):
            return True
        return False

    def pgd_index(self, pgd):
        return (pgd >> pgdir_shift) & (ptrs_per_pgd - 1)

    def get_pgd(self, vaddr):
        pgd_entry = self.dtb + self.pgd_index(vaddr) * pointer_size
        return self.read_long_phys(pgd_entry)

    def pte_pfn(self, pte):
        return pte >> page_shift

    def pte_index(self, pte):
        return (pte >> page_shift) & (ptrs_per_pte - 1)

    def get_pte(self, vaddr, pgd):
        pgd_val = pgd & ~((1 << page_shift) - 1)
        pgd_val = pgd_val + self.pte_index(vaddr) * pointer_size
        return self.read_long_phys(pgd_val)

    def get_paddr(self, vaddr, pte):
        return (self.pte_pfn(pte) << page_shift) | (vaddr & ((1 << page_shift) - 1))

    def get_four_meg_paddr(self, vaddr, pgd_entry):
        return (pgd_entry & ((ptrs_per_pgd - 1) << 22)) | (vaddr & ~((ptrs_per_pgd - 1) << 22))

    def get_prototype(self, vaddr, pte):
        '''
        Returns the offset in a 4KB memory page from the given
        Prototype PTE virtual address.
        The function returns either None (no valid mapping)
        or the offset in physical memory where the prototype maps

        See Windows Internals, 6th Edition, Part 2, pages 269-271
        and http://www.codemachine.com/article_protopte.html.
        '''
        if pte is None:
            return None

        if 0xfffff000 == (0xfffff000 & pte):
            # Add support for finding prototypes via VAD tree
            return None

        index_high = (pte & 0xffff800) >> 4
        index_low = (pte & 0xfe) >> 1
        prototype_vaddr = 0xe1000000 | (( index_high | index_low ) << 2)
        prototype_phys = self.vtop(prototype_vaddr)
        if prototype_phys is None:
            return None

        prototype_pte = self.read_long_phys(prototype_phys)
        if not self.entry_present(prototype_pte):
            return None

        return self.get_paddr(vaddr, prototype_pte)

    def get_pagefile(self, vaddr, pte, proto = False):
        '''
        Returns the offset in a 4KB memory page from the given
        Prototype PTE virtual address.
        The function returns either None (no valid mapping)
        or the offset in physical memory where the prototype maps

        See Windows Internals, 6th Edition, Part 2, pages 269-271
        and http://www.codemachine.com/article_protopte.html.
        '''
        if pte is None:
            return None

        pagefile_num = (pte >> 1) & 0xf
        pagefile_offset = (pte & 0xfffff000) + (vaddr & 0xfff)

        retAddr = 0
        if pagefile_offset == 0:
           # demand Zero
           if proto:
                pprofiler.profiling[self.name][pprofiler.DZ_PROTOTYPE] += 1
           else:
                pprofiler.profiling[self.name][pprofiler.DEMAND_ZERO] += 1
           retAddr = (0,0)
        else:
            if proto:
                pprofiler.profiling[self.name][pprofiler.PF_PROTOTYPE] += 1
            else:
                pprofiler.profiling[self.name][pprofiler.PAGEFILE] += 1
            retAddr = (pagefile_offset, "\pagefile.sys")

        return retAddr

    def vtop(self, vaddr):
        retVal = None
        pgd = self.get_pgd(vaddr)
        if self.entry_present(pgd):
            if self.page_size_flag(pgd):
                retVal = self.get_four_meg_paddr(vaddr, pgd)
            else:
                pte = self.get_pte(vaddr, pgd)
                if not pte:
                    return None
                if self.entry_present(pte):
                    retVal = self.get_paddr(vaddr, pte)
                else:
                    if self.use_prototype_ptes:
                        if self.entry_prototype(pte):
                            retVal = self.get_prototype(vaddr, pte)
                        if self.entry_pagefile(pte):
                            retVal = self.get_pagefile(vaddr, pte)
        return retVal

    def read_long_phys(self, addr):
        try:
            string = self.base.read(addr, 4)
        except IOError:
            string = None
        if not string:
            return obj.NoneObject("Unable to read_long_phys at " + hex(addr))
        (longval,) = struct.unpack('<I', string)
        return longval

    def read_long_long_phys(self, addr):
        '''
        This method returns a 64-bit little endian
        unsigned integer from the specified address in the
        physical address space. If the address cannot be accessed,
        then the method returns None.

        This code was derived directly from legacyintel.py
        '''
        try:
            string = self.base.read(addr, 8)
        except IOError:
            string = None
        if not string:
            return obj.NoneObject("Unable to read_long_long_phys at " + hex(addr))
        (longlongval,) = struct.unpack('<Q', string)
        return longlongval

    def get_available_pages(self):
        pgd_curr = self.dtb
        for i in range(0, ptrs_per_pgd):
            start = (i * ptrs_per_pgd * ptrs_per_pte * 4)
            entry = self.read_long_phys(pgd_curr)
            pgd_curr = pgd_curr + 4
            if self.entry_present(entry) and self.page_size_flag(entry):
                yield (start, 0x400000)
            elif self.entry_present(entry):
                pte_curr = entry & ~((1 << page_shift) - 1)
                for j in range(0, ptrs_per_pte):
                    pte_entry = self.read_long_phys(pte_curr)
                    pte_curr = pte_curr + 4
                    if self.entry_present(pte_entry):
                        yield (start + j * 0x1000, 0x1000)

class IA32PagedMemoryPae(IA32PagedMemory):
    """
    This class implements the IA-32 PAE paging address space. It is responsible
    for translating each 32-bit virtual (linear) address to a 52-bit physical address.
    When PAE paging is in use, CR3 references the base of a 32-Byte Page Directory
    Pointer Table.

    Additional Resources:
     - Intel(R) 64 and IA-32 Architectures Software Developer's Manual
       Volume 3A: System Programming Guide. Section 4.3
       http://www.intel.com/products/processor/manuals/index.htm
     - N. Petroni, A. Walters, T. Fraser, and W. Arbaugh, "FATKit: A Framework
       for the Extraction and Analysis of Digital Forensic Data from Volatile
       System Memory" ,Digital Investigation Journal 3(4):197-210, December 2006.
       (submitted February 2006)
     - N. P. Maclean, "Acquisition and Analysis of Windows Memory,"
       University of Strathclyde, Glasgow, April 2006.
     - Russinovich, M., & Solomon, D., & Ionescu, A.
       "Windows Internals, 5th Edition", Microsoft Press, 2009.
    """

    last_pte_vad = None
    last_vaddr = None
    order = 60
    pae = True

    def get_pdptb(self, pdpr):
        return pdpr & 0xFFFFFFE0

    def pdpi_index(self, pdpi):
        return (pdpi >> pdpi_shift)

    def get_pdpi(self, vaddr):
        pdpi_entry = self.get_pdptb(self.dtb) + self.pdpi_index(vaddr) * entry_size
        return self._read_long_long_phys(pdpi_entry)

    def pde_index(self, vaddr):
        return (vaddr >> pde_shift) & (ptrs_per_pde - 1)

    def pdba_base(self, pdpe):
        return pdpe & 0xFFFFFFFFFF000

    def get_pgd(self, vaddr, pdpe):
        pgd_entry = self.pdba_base(pdpe) + self.pde_index(vaddr) * entry_size
        return self._read_long_long_phys(pgd_entry)

    def pte_pfn(self, pte):
        return pte & 0xFFFFFFFFFF000

    def pte_index(self, vaddr):
        return (vaddr >> page_shift) & (ptrs_per_pde - 1)

    def ptba_base(self, pde):
        return pde & 0xFFFFFFFFFF000

    def get_pte(self, vaddr, pgd):
        pgd_val = self.ptba_base(pgd) + self.pte_index(vaddr) * entry_size
        return self._read_long_long_phys(pgd_val)

    def get_paddr(self, vaddr, pte):
        return self.pte_pfn(pte) | (vaddr & ((1 << page_shift) - 1))

    def get_large_paddr(self, vaddr, pgd_entry):
        return (pgd_entry & 0xFFFFFFFE00000) | (vaddr & ~((ptrs_page - 1) << 21))

    def find_pte_vad(self, vaddr):
        vaddrPageBase = vaddr & 0xFFFFF000

        # if we aquired a vadroot
        try:
            self.vadlookup
        except AttributeError:
            return None

        # If we need the last PTE again, load it from cache
        if vaddrPageBase != self.last_vaddr:
            # Find the vad that contains our address
            try:
                self.last_pte_vad = self.vadlookup[vaddr]
            except KeyError:
                return None
            # if succeed save it to cache
            self.last_vaddr = vaddrPageBase

        #if self.last_pte_vad == None:
        #    return None

        pageNum = (vaddrPageBase - self.last_pte_vad.Start) / 0x1000
        prototype_vaddr =  self.last_pte_vad.FirstPrototypePte.v() + (pageNum*8)
        return (prototype_vaddr, self.last_pte_vad, pageNum)

    def get_zeropte(self, vaddr):
        '''
        Kikeressuk a PTE-t a VAD-okat leiro PTE-k kozul
        '''
        pte_vad = self.find_pte_vad(vaddr)
        if pte_vad == None:
            return 0
        # unpack the return value
        (prototype_vaddr, currentVad, pageNum) = pte_vad

        # read the pte from physical memory
        prototype_phys = self.vtop(prototype_vaddr)
        if prototype_phys == None:
            return 0
        return self.read_long_long_phys(prototype_phys)

    def get_subsection(self, vaddr, pte):
        subsection_addr = (pte & 0xffffffff00000000) >> 32
        subsection = obj.Object("_SUBSECTION", subsection_addr, self)
        if subsection == None:
            pprofiler.profiling[self.name][pprofiler.MAPPED_FILE_UNKNOWN] += 1
            return None
        control_area = obj.Object("_CONTROL_AREA", subsection.ControlArea.v(), self)
        file_object = control_area.FilePointer.dereference_as("_FILE_OBJECT") # TODO zero check
        FileName = str(file_object.FileName)

        pte_vad = self.find_pte_vad(vaddr)
        if pte_vad == None:
            return None
        (pte_addr, currentVad, pageNum) = pte_vad

        StartingSector = subsection.StartingSector
        SubsectionOffset = StartingSector * 0x200
        ptrNum = (pte_addr - subsection.SubsectionBase) / 8

        FileOffset = SubsectionOffset + (ptrNum * 0x1000) + (vaddr & ((1 << page_shift) - 1))
        pprofiler.file_objects[self.name].add(FileName)
        return (FileOffset, FileName)

    def get_prototype(self, vaddr, pte):
        '''
        Returns the offset in a 4KB memory page from the given
        Prototype PTE virtual address.
        The function returns either None (no valid mapping)
        or the offset in physical memory where the prototype maps

        See Windows Internals, 6th Edition, Part 2, pages 269-271
        and http://www.codemachine.com/article_protopte.html.
        '''
        if pte is None:
            return None

        if 0xffffffff00000000 == (0xfffffffffffff000 & pte):
            pte_vad = self.find_pte_vad(vaddr)
            if pte_vad == None:
                return None
            # unpack the return value
            (prototype_vaddr, currentVad, pageNum) = pte_vad
        else:
            currentVad = None
            prototype_vaddr = (pte & 0xffffffff00000000) >> 32

        # read the prototype pte from physical memory
        prototype_phys = self.vtop_proto(prototype_vaddr)
        if prototype_phys is None:
            pprofiler.profiling[self.name][pprofiler.PROTO_INVALID] += 1
            debug.debug("Invalid Proto PTE: " + hex(vaddr) + " type: " + hex(pte))
            return None

        prototype_pte = self.read_long_long_phys(prototype_phys)

        retVal = None
        # check if this prototype entry is in memory
        if self.entry_present(prototype_pte):
            pprofiler.profiling[self.name][pprofiler.PROTO_VALID] += 1
            retVal = self.get_paddr(vaddr, prototype_pte)
        elif self.entry_pagefile(prototype_pte):
            return self.get_pagefile(vaddr, prototype_pte, True)
        elif self.entry_prototype(prototype_pte):
            if self.entry_subsection(prototype_pte):
                pprofiler.profiling[self.name][pprofiler.MAPPED_FILE_PROTO] += 1
                return self.get_subsection(vaddr, prototype_pte)
            else:
                pprofiler.profiling[self.name][pprofiler.PROTO_UNKNOWN] += 1
                debug.debug("Unknown prototype PTE: " + hex(vaddr) + " type: " + str(prototype_pte))
        else:
            #retVal = self.get_zeropte(vaddr)
            #prototype_pte: 128 demand zero
            pprofiler.profiling[self.name][pprofiler.PROTO_UNKNOWN] += 1
            debug.debug("Unknown prototype PTE: " + hex(vaddr) + " type: " + str(prototype_pte))
        return retVal

    def vtop_proto(self, proto_vaddr):
        '''
        Feltetelezem hogy maga a hivatkozott Prototype PTE, nem lehet LARGE, illetve EMPTY PTE-ken tarolva
        '''
        retVal = None
        pdpe = self.get_pdpi(proto_vaddr)
        if not self.entry_present(pdpe):
            return retVal
        pgd = self.get_pgd(proto_vaddr, pdpe)
        if self.entry_present(pgd):
            if not self.page_size_flag(pgd):
                pte = self.get_pte(proto_vaddr, pgd)
                if self.entry_present(pte):
                    retVal = self.get_paddr(proto_vaddr, pte)

        return retVal

    def profile_pte_flags(self, pxx):
        writeable = (pxx & 0b10) == 0b10
        kernel_mode = (pxx & 0b100) == 0
        cache_writeback = (pxx & 0b1000) == 0
        cache = (pxx & 0b10000) == 0
        accessed = (pxx & 0b100000) == 0b100000
        dirty = (pxx & 0b1000000) == 0b1000000
        copyonwrite = (pxx & 0b1000000000) == 0b1000000000
        nx = (pxx & (1 << 63)) != 0

        if nx:
            pprofiler.profiling[self.name][pprofiler.NX] += 1
        if writeable:
            pprofiler.profiling[self.name][pprofiler.WRITEABLE] += 1
        if kernel_mode:
                pprofiler.profiling[self.name][pprofiler.KERNEL_MODE] += 1
        if cache_writeback:
            pprofiler.profiling[self.name][pprofiler.CACHE_WRITEBACK] += 1
        if cache:
            pprofiler.profiling[self.name][pprofiler.CACHE] += 1
        if accessed:
            pprofiler.profiling[self.name][pprofiler.ACCESSED] += 1
        if dirty:
            pprofiler.profiling[self.name][pprofiler.DIRTY] += 1
        if copyonwrite:
            pprofiler.profiling[self.name][pprofiler.COPYONWRITE] += 1

    def process_entry(self, vaddr, pgd, pte):
        retVal = None
        if (pgd & 0b100000000) == 0b100000000:
            pprofiler.profiling[self.name][pprofiler.GLOBAL_PDE] += 1
        # If large page flag is set in PGD
        if self.page_size_flag(pgd):
            pprofiler.profiling[self.name][pprofiler.LARGE] += 1
            retVal = self.get_large_paddr(vaddr, pgd)
        else:
            # if PTE still zero, return none
            if pte == 0:
                pprofiler.profiling[self.name][pprofiler.EMPTY_PTE] += 1
                #Reserved, but not committed page
                return (0,0)
            self.profile_pte_flags(pte)
            if self.entry_present(pte):
                pprofiler.profiling[self.name][pprofiler.VALID] += 1
                retVal = self.get_paddr(vaddr, pte)
            # if valid PTE, resolve type
            elif self.entry_prototype(pte):
                if self.entry_subsection(pte):
                    pprofiler.profiling[self.name][pprofiler.MAPPED_FILE] += 1
                    retVal = self.get_subsection(vaddr, pte)
                else:
                    retVal = self.get_prototype(vaddr, pte)
            elif self.entry_pagefile(pte):
                #pprofiler.profiling[self.name][pprofiler.PAGEFILE] += 1
                retVal = self.get_pagefile(vaddr, pte)
            else:
                pprofiler.profiling[self.name][pprofiler.UNKNOWN] += 1
                if vaddr != 0:
                    debug.debug("Unknown PTE: " + hex(vaddr))
        return retVal

    def vtop(self, vaddr):
        # if we have an invalid address 0?
        if vaddr == 0:
            return None
        # try to search in PDP table
        pdpe = self.get_pdpi(vaddr)
        if not self.entry_present(pdpe):
            pprofiler.profiling[self.name][pprofiler.EMPTY_PDPE] += 1
            return (0,0)
        # find the PGD in PDP
        pgd = self.get_pgd(vaddr, pdpe)
        pte = 0
        # If invalid PGD present for a valid address, search the representing PTE in VAD
        if (not self.entry_present(pgd)) or pgd == 0:
            pte = self.get_zeropte(vaddr)
        # IF we had a valid PGD, get the corresponding PTE
        else:
            # first try to get the entry as usual
            pte = self.get_pte(vaddr, pgd)
            # if PTE still zero, try to find it in VAD
            if pte == 0:
                pte = self.get_zeropte(vaddr)

        return self.process_entry(vaddr, pgd, pte)

    def _read_long_long_phys(self, addr):
        if not addr:
            return obj.NoneObject("Unable to read None")

        try:
            string = self.base.read(addr, 8)
        except IOError:
            string = None
        if not string:
            return obj.NoneObject("Unable to read base AS at " + hex(addr))
        (longlongval,) = struct.unpack('<Q', string)
        return longlongval

    def get_available_pages(self):

        pdpi_base = self.get_pdptb(self.dtb)

        for i in range(0, ptrs_per_pdpi):

            start = (i * ptrs_per_pae_pgd * ptrs_per_pae_pgd * ptrs_per_pae_pte * 8)
            pdpi_entry = pdpi_base + i * entry_size
            pdpe = self._read_long_long_phys(pdpi_entry)

            if not self.entry_present(pdpe):
                continue

            pgd_curr = self.pdba_base(pdpe)

            for j in range(0, ptrs_per_pae_pgd):
                soffset = start + (j * ptrs_per_pae_pgd * ptrs_per_pae_pte * 8)
                entry = self._read_long_long_phys(pgd_curr)
                pgd_curr = pgd_curr + 8
                if self.entry_present(entry) and self.page_size_flag(entry):
                    yield (soffset, 0x200000)
                elif self.entry_present(entry):
                    pte_curr = entry & ~((1 << page_shift) - 1)
                    for k in range(0, ptrs_per_pae_pte):
                        pte_entry = self._read_long_long_phys(pte_curr)
                        pte_curr = pte_curr + 8
                        if self.entry_present(pte_entry):
                            yield (soffset + k * 0x1000, 0x1000)
