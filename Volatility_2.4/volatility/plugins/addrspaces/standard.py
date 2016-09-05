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

""" These are standard address spaces supported by Volatility """
import struct
import volatility.addrspace as addrspace
import volatility.debug as debug #pylint: disable-msg=W0611
import urllib
import os
import sys
import traceback
import collections

#pylint: disable-msg=C0111

def write_callback(option, _opt_str, _value, parser, *_args, **_kwargs):
    """Callback function to ensure that write support is only enabled if user repeats a long string
    
       This call back checks whether the user really wants write support and then either enables it
       (for all future parses) by changing the option to store_true, or disables it permanently
       by ensuring all future attempts to store the value store_false.
    """
    if not hasattr(parser.values, 'write'):
        # We don't want to use config.outfile, since this should always be seen by the user
        option.dest = "write"
        option.action = "store_false"
        parser.values.write = False
        for _ in range(3):
            testphrase = "Yes, I want to enable write support"
            response = raw_input("Write support requested.  Please type \"" + testphrase +
                                 "\" below precisely (case-sensitive):\n")
            if response == testphrase:
                option.action = "store_true"
                parser.values.write = True
                return
        print "Write support disabled."

class FileAddressSpace(addrspace.BaseAddressSpace):
    """ This is a direct file AS.

    For this AS to be instantiated, we need

    1) A valid config.LOCATION (starting with file://)

    2) no one else has picked the AS before us
    
    3) base == None (we dont operate on anyone else so we need to be
    right at the bottom of the AS stack.)
    """
    ## We should be the AS of last resort
    order = 100
    def __init__(self, base, config, layered = False, **kwargs):
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)
        self.as_assert(base == None or layered, 'Must be first Address Space')
        self.as_assert(config.LOCATION.startswith("file://"), 'Location is not of file scheme')

        path = urllib.url2pathname(config.LOCATION[7:])
        self.as_assert(os.path.exists(path), 'Filename must be specified and exist')
        self.name = os.path.abspath(path)
        self.fname = self.name
        self.mode = 'rb'
        if config.WRITE:
            self.mode += '+'
        self.fhandle = open(self.fname, self.mode)
        self.fhandle.seek(0, 2)
        self.fsize = self.fhandle.tell()

    # Abstract Classes cannot register options, and since this checks config.WRITE in __init__, we define the option here
    @staticmethod
    def register_options(config):
        config.add_option("WRITE", short_option = 'w', action = "callback", default = False,
                          help = "Enable write support", callback = write_callback)

    def fread(self, length):
        length = int(length)
        return self.fhandle.read(length)

    def read(self, addr, length):
        addr, length = int(addr), int(length)
        try:
            self.fhandle.seek(addr)
        except (IOError, OverflowError):
            return None
        data = self.fhandle.read(length)
        if len(data) == 0:
            return None
        return data

    def zread(self, addr, length):
        data = self.read(addr, length)
        if data is None:
            data = "\x00" * length
        elif len(data) != length:
            data += "\x00" * (length - len(data))
        return data

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval,) = struct.unpack('=I', string)
        return longval

    def get_available_addresses(self):
        # Since the second parameter is the length of the run
        # not the end location, it must be set to fsize, not fsize - 1
        yield (0, self.fsize)

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return 0 <= addr < self.fsize

    def close(self):
        self.fhandle.close()

    def write(self, addr, data):
        if not self._config.WRITE:
            return False
        try:
            self.fhandle.seek(addr)
            self.fhandle.write(data)
        except IOError:
            return False
        return True

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.base == other.base and hasattr(other, "fname") and self.fname == other.fname

class DynamicFileAddressSpace(FileAddressSpace):
    # We should try to instantiate it before normal file address space
    order = 99
    used_files = collections.defaultdict(lambda: collections.defaultdict(str))
    currentPath = ''

    def __init__(self, base, config, layered = False, **kwargs):
        FileAddressSpace.__init__(self, base, config, layered, **kwargs)
        self.as_assert(('mountdrive' in config.opts), "No mounted drive found")
        self.mntdrive = config.MOUNTDRIVE

    def convert_path(self, path):
        separator = os.path.sep
        if separator != '\\':
            path = path.replace('\\', separator)
        return path

    def reload_file(self, path):
        def assign_used_file():
            self.currentPath = path
            self.fname = self.used_files[path]['fname']
            self.name = self.used_files[path]['fname']
            self.mode = self.used_files[path]['mode']
            self.fhandle = self.used_files[path]['fhandle']
            self.fhandle.seek(0, 2)
            self.fsize = self.used_files[path]['fsize']

        if path in self.used_files:
            if self.currentPath == path:
                return
            assign_used_file()
        else:
            debug.debug('read from file: ' + path)
            path_name = urllib.url2pathname(path)
            if not os.path.exists(path_name):
                debug.warning('File not exist: ' + path + ' Returning zero bytes..')
                currentPath = 'ZERO'
                return
            # assert os.path.exists(path_name), 'Filename must be specified and exist'
            self.used_files[path]['fname'] = os.path.abspath(path_name)
            self.used_files[path]['mode'] = 'rb'
            if self._config.WRITE:
                self.used_files[path]['mode'] += '+'
            self.used_files[path]['fhandle'] = open(self.used_files[path]['fname'], self.used_files[path]['mode'])
            self.used_files[path]['fsize'] = self.fhandle.tell()
            assign_used_file()


    def is_valid_address(self, addr):
        if addr == None:
            return False
        if isinstance(addr, tuple):
            # Demand zero lapok mindig validok
            if addr == (0,0):
                return True
            else:
                filepath = self.convert_path(str(addr[1]))
                offset = addr[0]
                self.reload_file(self.mntdrive + filepath)
        return 0 <= addr < self.fsize

    def read(self, addr, length):
        if isinstance(addr, tuple):
            # Ures teruletet adhatunk vissza ilyenkor
            if addr == (0,0):
                data = "\x00" * length
                return data
            # Decompose tuple
            filepath = self.convert_path(str(addr[1]))
            addr = int(addr[0])
            self.reload_file(self.mntdrive + filepath)
        else:
            self.reload_file(self._config.LOCATION[7:])
            addr = int(addr)

        if self.currentPath == 'ZERO':
            data = "\x00" * length
            return data

        length = int(length)
        self.fhandle.seek(addr)
        data = self.fhandle.read(length)
        if len(data) == 0:
            return None

        # Pad the data from file to page size
        if isinstance(addr, tuple):
            if len(data) < length:
                data += (length - len(data)) * "\x00"

        return data
