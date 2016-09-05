# -*- coding: utf-8 -*-
#title           :page_test_flame.py
#description     :Run page test on flame. 
#author          :zslazar
#date            :20140923
#usage           :python page_test.py -disk "/home/zslazar/TestDisk" -vol "/home/zslazar/Volatility_2.4" -fdir "/home/zslazar/snapshots_1tera/flame" -odir "/home/zslazar/page_test"
#python_version  :2.7.6
#==============================================================================
	
import argparse
import os
import time
import re
import subprocess
import fnmatch
import glob
import sys

NBD_TIMEOUT = 10
NBD_INTERVAL = 0.2

# Errors' exit codes
ERR_OK = 0
ERR_NODE_NOT_PRESENT = 3
ERR_LOAD_NBD = 4
ERR_CONNECT_NBD = 5
ERR_UNMOUNT = 6
ERR_NO_WINDOWS = 7
ERR_DISCONNECT_NBD = 8
ERR_NO_VHD = 18
ERR_MULTIPLE_ERRORS = 17
ERR_UNKNOWN = 255

ErrorCode = ERR_OK

parser = argparse.ArgumentParser();
parser.add_argument("-vol", help="Volatility directory", type=str, required=True)
parser.add_argument("-disk", help="Mounted disk directory", type=str, required=True)
parser.add_argument("-fdir", help="Malware snapshot directory", type=str, required=True)
parser.add_argument("-odir", help="Output directory for page tests", type=str, required=True)
parser.add_argument("-vmdk", help="Fix the VMDKs only", action='store_true', required=False)
parser.add_argument("-time", help="Run time in seconds", type=str, required=True)
args = parser.parse_args()

output = sys.stdout

class PrepareException(Exception):
    
    def __init__(self, value, code):
        global ErrorCode
        self.value = value
        ErrorCode = code
    def __str__(self):
        return str(self.value)

def get_node_ignore_case(directory, pattern):

    """
    Returns the first node path in a specified directory, where the node
    matches with the pattern, case sensitivly. If not found any node,
    returns with None.
    """
    cre = re.compile(fnmatch.translate(pattern), re.IGNORECASE)
    for node in os.listdir(directory):
        if cre.match(node):
            return directory+"/"+node
    else:
        return None


def wait_for(node, timeout, interval):
    """
    It waits for a file, to be appeared. If timeout reached, an
    exception will be raised.
    """
    time_left = timeout
    while not time_left < 0:
        if os.path.exists(node):
            break
        else:
            time.sleep(interval)
            time_left = time_left - interval
    else:
        raise PrepareException("The node "+node+" has not appeared in the given time.", ERR_NODE_NOT_PRESENT)

def get_partition_count(device):
    """Returns the partition count in the given device."""
    bstr = subprocess.check_output(["parted", "-s", "-m", device, "print"])
    return len(re.findall(b"^[0-9]+:", bstr, re.MULTILINE))  # In case of minor changes in parted's output

def mount_system_partition(vhd, nbd, mpoint):
    """
    Finds and mounts a given virtual drive's partition, which contains Windows operating system.
    It uses for this operation, a given Network Block Device and Mount Point.
    The partition will be mounted on the given Mount Point.
    If no partition found, that suffices the condiions, it raises an exception.
    """
    if subprocess.call(["modprobe", "nbd"]) != 0:
        raise PrepareException("Could not load module \'nbd\'.", ERR_LOAD_NBD)
    if subprocess.call(["qemu-nbd", "-c", nbd, vhd]) != 0:  # qemu-img could be used to convert between image types
        raise PrepareException("Could not connect virtual harddisk as a Network Block Device.", ERR_CONNECT_NBD)
    
    for partnum in range(1, get_partition_count(device=nbd)+1):
        part = nbd + "p" + str(partnum)
        print("DEBUG: Trying "+part)
        wait_for(node=part, timeout=NBD_TIMEOUT, interval=NBD_INTERVAL)
        
        if subprocess.call(["mount", part, mpoint]) != 0:
            continue
        if get_node_ignore_case(directory=mpoint, pattern="windows") is not None:
            break
        if subprocess.call(["umount", mpoint]) != 0:
            raise PrepareException("Could not unmount partition.", ERR_UNMOUNT)
    else:
        raise PrepareException("Windows has not been found on any partition.", ERR_NO_WINDOWS)
    
def unmount_system_partition(nbd, mpoint):
    """
    UnMount the partition in given Mount Point, and disconnects the Network Block Device.
    The exceptions are handled in this piece of code.
    """
    global ErrorCode
    
    if subprocess.call(["umount", mpoint]) != 0:
        print("Could not unmount system partition.")
        if ErrorCode == ERR_OK:
            ErrorCode = ERR_UNMOUNT
        else:
            ErrorCode = ERR_MULTIPLE_ERRORS
    
    if subprocess.call(["qemu-nbd", "-d", nbd]) != 0:
        print("Could not disconnect Network Block Device.")
        if ErrorCode == ERR_OK:
            ErrorCode = ERR_DISCONNECT_NBD
        else:
            ErrorCode = ERR_MULTIPLE_ERRORS

def check_copy_done(filename):
    while True:
        size_before = os.stat(filename).st_size
        time.sleep( 1 )
        size_after = os.stat(filename).st_size
        if size_before == size_after:
            return

mtime = lambda f: os.stat(os.path.join(args.fdir, f)).st_mtime            

def run_number_sort(sample):
    if '.vmsn' not in sample:
        return 100

    if '!Windows_7_x64' in sample:
        return 100

    name_split = sample.split('__test')
    run_number = int(name_split[1].split('_')[0])
    return run_number

for sample in sorted(os.listdir(args.fdir), reverse=True, key=run_number_sort):
    if '.vmsn' not in sample:
        continue

    if '!Windows_7_x64' in sample:
	continue

    # Name of files required for analyzis
    out_name = sample.split('.vmsn')[0] + '.csv'
    name_split = sample.split('__test')
    run_number = name_split[1].split('_')[0]
    dvmdk_name = name_split[0] + '__test-delta' + run_number + '_' + args.time + 'sec' + '.vmdk'
    base_name = args.fdir + '/' + sample.split('.vmsn')[0]
    vmsn_path = base_name + '.vmsn'
    vmdk_path = base_name + '.vmdk'
    dvmdk_path = args.fdir + '/' + dvmdk_name

    if out_name in os.listdir(args.odir):       
        continue

    print >> sys.stderr, '[+]Test started on: ' + base_name
        
    # If copy in progress wait
    if not args.vmdk:
        check_copy_done(vmsn_path)
        check_copy_done(vmdk_path)
        check_copy_done(dvmdk_path)
        
        print >> sys.stderr, '[+]Acquired all files'
    
    profile = "Win7SP1x64" #default
    with open(vmdk_path, 'rw+') as content_file:
        content = content_file.read()
        # Choose profile from vmdk descriptor
        #if content.find('Windows_7') != -1:
        #    profile = 'Win7SP1x86'
        
        # Change the delta VMDK name
        vmdk_path_start = content.find('VMFSSPARSE "') + len('VMFSSPARSE "')
        vmdk_path_end = content.find('"', vmdk_path_start)
        changed_content = content[:vmdk_path_start] + dvmdk_name + content[vmdk_path_end:]
       
        # Change the parent hint
        vmdk_path_start = changed_content.find('parentFileNameHint="') + len('parentFileNameHint="')
        vmdk_path_end = changed_content.find('"', vmdk_path_start)

        run0_parent = '/home/zslazar_sshfs/snapshots_kettera2/W7x64Periodic/!Windows_7_x64.vmdk'
        if run_number == '0':
            changed_content = changed_content[:vmdk_path_start] + run0_parent + changed_content[vmdk_path_end:]
        else:
            prev_parent = base_name.split('__test')[0] + '__test' + str(int(run_number)-1) + '_' + args.time + 'sec.vmdk'
            changed_content = changed_content[:vmdk_path_start] + prev_parent + changed_content[vmdk_path_end:]

        content_file.seek(0)
        content_file.truncate()
        content_file.write(changed_content)
            
    print >> sys.stderr, '[+]Profile chosen: ' + profile
    output.flush()
    #print >> sys.stderr, '[+]Profile chosen: ' + profile
    print >> sys.stderr, '[+]Delta VMDK name modified in descriptor'
    #print >> sys.stderr, '[+]Delta VMDK name modified in descriptor'
    if not args.vmdk:
        print args.disk
        print vmdk_path
        unmount_system_partition('/dev/nbd2', args.disk)
        mount_system_partition(vmdk_path, '/dev/nbd2', args.disk)
        print '[+]VMDK mounted for test'

        # Start volatility
        cmd_list = []
        cmd_list.append('python2')
        cmd_list.append(args.vol + '/vol.py')
        cmd_list.append('yarascan')
        cmd_list.append('--profile=' + profile)
        cmd_list.append('-f')
        cmd_list.append(vmsn_path)
        cmd_list.append('-Y')
        cmd_list.append('asdASD')
        cmd_list.append('--profiledir=' + args.odir)
        cmd_list.append('--mountdrive=' + args.disk)

        try:
            print >> output, subprocess.check_output(cmd_list) # automatic wait for end
        except subprocess.CalledProcessError:
            print >> sys.stderr, "[-] Non Zero return for current image."

    output.flush()
    if output != sys.stdout:
        output.close()
