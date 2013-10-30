#!/usr/bin/env python

'''
Recomposer.py 
Author Joshua Pitts the.midnite.runr 'at' gmail <d ot > com

Copyright (C) 2013, Joshua Pitts

License:   GPLv3

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

See <http://www.gnu.org/licenses/> for a copy of the GNU General
Public License

Currently supports win32/64 EXEs/DLLs only (intel architecture).
This program is to be used for only legal activities by IT security
professionals and researchers. Author not responsible for malicious
uses.
'''
'''
To do:
Automatic log_recomposer.txt.
    Original_FIle|NewFile

'''

from optparse import OptionParser
import struct
import operator
import shutil
import os
import string
import random
import sys
import hashlib

global flItms
global f
global verbose
verbose = False

exit_values = ['quit', 'q', 'done', 'exit']

MachineTypes = {'0x0': 'AnyMachineType',
                '0x1d3': 'Matsushita AM33',
                '0x8664': 'x64',
                '0x1c0': 'ARM LE',
                '0x1c4': 'ARMv7',
                '0xaa64': 'ARMv8 x64',
                '0xebc': 'EFIByteCode',
                '0x14c': 'Intel x86',
                '0x200': 'Intel Itanium',
                '0x9041': 'M32R',
                '0x266': 'MIPS16',
                '0x366': 'MIPS w/FPU',
                '0x466': 'MIPS16 w/FPU',
                '0x1f0': 'PowerPC LE',
                '0x1f1': 'PowerPC w/FP',
                '0x166': 'MIPS LE',
                '0x1a2': 'Hitachi SH3',
                '0x1a3': 'Hitachi SH3 DSP',
                '0x1a6': 'Hitachi SH4',
                '0x1a8': 'Hitachi SH5',
                '0x1c2': 'ARM or Thumb -interworking',
                '0x169': 'MIPS little-endian WCE v2'
                }

supported_types = ['Intel x86', 'x64']

safe_section_additions = ['FUTURE_USE_1', 'FUTURE_USE_2', 'FUTURE_USE_3',
                          'FUTURE_USE_4', 'FUTURE_USE_5', 'IMAGE_SCN_CNT_CODE',
                          'IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_WRITE',
                          'IMAGE_SCN_MEM_READ', 'IMAGE_SCN_MEM_EXECUTE', 
                          'IMAGE_SCN_MEM_SHARED']

nops = [0x90, 0x3690, 0x6490, 0x6590, 0x6690, 0x6790]


section_flags = {"Group1":
                {"FUTURE_USE_1": 0x00000001,
                 "FUTURE_USE_2": 0x00000002,
                 "FUTURE_USE_3": 0x00000004,
                 "IMAGE_SCN_TYPE_NO_PAD": 0x00000008,
                 },
                 "Group2":
                 {"FUTURE_USE_4":       0x00000010,
                  "IMAGE_SCN_CNT_CODE": 0x00000020,
                  "IMAGE_SCN_CNT_INITIALIZED_DATA": 0x00000040,
                  "IMAGE_SCN_CNT_UNINITIALIZED_DATA": 0x00000080,
                  },
                 "Group3":
                 {"IMAGE_SCN_LNK_OTHER": 0x00000100,
                  "IMAGE_SCN_LNK_INFO": 0x00000200,
                  "FUTURE_USE_5": 0x00000400,
                  "IMAGE_SCN_LNK_REMOVE": 0x00000800,
                  },
                 "Group4":
                 {"IMAGE_SCN_LNK_COMDAT": 0x00001000,
                  "IMAGE_SCN_GPREL": 0x00008000,
                  },
                 "Group5":
                 {"IMAGE_SCN_MEM_PURGEABLE": 0x00020000,
                  "IMAGE_SCN_MEM_LOCKED": 0x00040000,
                  "IMAGE_SCN_MEM_PRELOAD": 0x00080000,
                  },
                 "Group6":
                 {"IMAGE_SCN_ALIGN_1BYTES": 0x00100000,
                  "IMAGE_SCN_ALIGN_2BYTES": 0x00200000,
                  "IMAGE_SCN_ALIGN_4BYTES": 0x00300000,
                  "IMAGE_SCN_ALIGN_8BYTES": 0x00400000,
                  "IMAGE_SCN_ALIGN_16BYTES": 0x00500000,
                  "IMAGE_SCN_ALIGN_32BYTES": 0x00600000,
                  "IMAGE_SCN_ALIGN_64BYTES": 0x00700000,
                  "IMAGE_SCN_ALIGN_128BYTES": 0x00800000,
                  "IMAGE_SCN_ALIGN_256BYTES": 0x00900000,
                  "IMAGE_SCN_ALIGN_512BYTES": 0x00A00000,
                  "IMAGE_SCN_ALIGN_1024BYTES": 0x00B00000,
                  "IMAGE_SCN_ALIGN_2048BYTES": 0x00C00000,
                  "IMAGE_SCN_ALIGN_4096BYTES": 0x00D00000,
                  "IMAGE_SCN_ALIGN_8192BYTES": 0x00E00000,
                  },
                 "Group7":
                 {"IMAGE_SCN_LNK_NRELOC_OVFL": 0x01000000,
                  "IMAGE_SCN_MEM_DISCARDABLE": 0x02000000,
                  "IMAGE_SCN_MEM_NOT_CACHED": 0x04000000,
                  "IMAGE_SCN_MEM_NOT_PAGED": 0x08000000,
                  },
                 "Group8":
                 {"IMAGE_SCN_MEM_SHARED": 0x10000000,
                  "IMAGE_SCN_MEM_EXECUTE": 0x20000000,
                  "IMAGE_SCN_MEM_READ": 0x40000000,
                  "IMAGE_SCN_MEM_WRITE": 0x80000000,
                  }
                 }

sectionflag_help= ("""
LEGEND:
Section Flags Example: 0x40000040
Group:  8   7   6   5   4   3   2   1
      0x4   0   0   0   0   0   4   0 

Group3                  Group2                              Group1:
IMAGE_SCN_LNK_OTHER     FUTURE_USE_4                        FUTURE_USE_1
IMAGE_SCN_LNK_INFO      IMAGE_SCN_CNT_CODE                  FUTURE_USE_2
FUTURE_USE_5            IMAGE_SCN_CNT_INITIALIZED_DATA      FUTURE_USE_3
IMAGE_SCN_LNK_REMOVE    IMAGE_SCN_CNT_UNINITIALIZED_DATA    IMAGE_SCN_TYPE_NO_PAD
     
Group6:                     Group5:                         Group4:
IMAGE_SCN_ALIGN_1BYTES      IMAGE_SCN_MEM_PURGEABLE         IMAGE_SCN_LNK_COMDAT
IMAGE_SCN_ALIGN_2BYTES      IMAGE_SCN_MEM_LOCKED            IMAGE_SCN_GPREL
IMAGE_SCN_ALIGN_4BYTES      IMAGE_SCN_MEM_PRELOAD        
IMAGE_SCN_ALIGN_8BYTES
IMAGE_SCN_ALIGN_16BYTES     Group7:
IMAGE_SCN_ALIGN_32BYTES     IMAGE_SCN_LNK_NRELOC_OVFL
IMAGE_SCN_ALIGN_64BYTES     IMAGE_SCN_MEM_DISCARDABLE
IMAGE_SCN_ALIGN_128BYTES    IMAGE_SCN_MEM_NOT_CACHED
IMAGE_SCN_ALIGN_256BYTES    IMAGE_SCN_MEM_NOT_PAGED
IMAGE_SCN_ALIGN_512BYTES    
IMAGE_SCN_ALIGN_1024BYTES   Group8:
IMAGE_SCN_ALIGN_2048BYTES   IMAGE_SCN_MEM_SHARED
IMAGE_SCN_ALIGN_4096BYTES   IMAGE_SCN_MEM_EXECUTE
IMAGE_SCN_ALIGN_8192BYTES   IMAGE_SCN_MEM_READ
                            IMAGE_SCN_MEM_WRITE
   """)


def md5_for_file(FILE, block_size=2**20):
    """
    Modded from stackoverflow: 
    http://stackoverflow.com/questions/1131220/get-md5-hash-of-big-files-in-python
    """
    md5 = hashlib.md5()
    filehandle = open(FILE, 'r+b')
    while True:
        data = filehandle.read(block_size)
        if not data:
            break
        md5.update(data)
    filehandle.close()
    return md5.hexdigest()


def random_name_return(len):
    '''
    Returns a random name of alphanumeric chars
    based on input length
    '''
    chars = string.digits + string.ascii_uppercase + string.ascii_lowercase
    name = ''
    for i in range(0, len):
        name += random.choice(chars)
    return name


def return_filename(outputfile):
    os_name = os.name
    if not os.path.exists("updatedfile"):
        os.makedirs("updatedfile")
    if os_name == 'nt':
        updatedfile = "updatedfile\\" + outputfile
    else:
        updatedfile = "updatedfile/" + outputfile
    
    return updatedfile


def randomly_change_file(FILE, DISK_OFFSET):
    global flItms
    global f
    flItms = {}
    print "Old file name:", FILE
    flItms['filename'] = FILE
    #make random file name 4-13 char in len
    new_file_name = random_name_return(random.randrange(4,14)) + ".exe"
    print "New file name:", new_file_name
    new_file_name = return_filename(new_file_name)
    flItms['outputfile'] = new_file_name
    #print flItms['outputfile']
    shutil.copy2(flItms['filename'], flItms['outputfile'])
    flItms = support_check(flItms['outputfile'], DISK_OFFSET)
    flItms['outputfile'] = new_file_name
    f = open(flItms['outputfile'], "r+b")
    for i, section in enumerate(flItms['Sections']):
        print i+1, "Section:", section[0], "| SectionFlags:", hex(section[9])
    get_section_attributes(flItms)
    find_cave(flItms, 20)
        
    for i, section in enumerate(flItms['Sections']):
        if random.random() > .49999999999:
            addflags = True
            #Enumerate Sections
            defaultattrib = []
            for attrib in flItms['FlagAttributes'][flItms['Sections'][i][0]]:
                defaultattrib.append(attrib)
            section_overlap = []
            for item in defaultattrib:
                for item1 in safe_section_additions:
                    if item1 in item:
                        section_overlap.append(item1)
            temp_sections = safe_section_additions[:]
            for k, item in enumerate(section_overlap):
                temp_sections.remove(item)
            attributeStore = set()
            for k in range(random.randrange(1, len(temp_sections))):
                attributeStore.add(random.choice(temp_sections))
            new_value = change_section_flags(flItms, flItms['Sections'][i], attributeStore)   
            flItms['Sections'][i][9] = new_value
        else:
            addflags = False
        newSectionName = random_name_return(random.randrange(2, 8))
        newSectionName = newSectionName + ((7 - len(newSectionName)) * "\x00")
        change_section_name(flItms, flItms['Sections'][i][0], newSectionName)
        
    
    
    f.close()
    print "Updated Binary:"
    print "\t" + flItms['outputfile']
    f = open(flItms['outputfile'], "r+b")
    flItms = support_check(flItms['outputfile'], DISK_OFFSET)
    for i, section in enumerate(flItms['Sections']):
        print i+1, "Section:", section[0], "| SectionFlags:", hex(section[9])
    f.close()
    print "Writing to log_recomposer.txt"
    g = open("log_recomposer.txt",'a')
    g.write(FILE + '|' + md5_for_file(FILE) + '|')
    g.write(new_file_name + '|' + md5_for_file(new_file_name) + '\n')
    g.close()


def change_binary_workflow(FILE, OUTPUT, DISK_OFFSET):
    """
    Workflow to change the sections:

        What sections would you like to change?
        print sections
        Current flags
        What flags would you like to use:
        print all flags
    """
    global flItms
    flItms = {}
    flItms['filename'] = FILE
    if OUTPUT == "":
        outputfile = return_filename("change." + os.path.basename(FILE))
    else:
        outputfile = return_filename(os.path.basename(OUTPUT))

    shutil.copy2(flItms['filename'], outputfile)
    flItms = support_check(outputfile, DISK_OFFSET)
    global f
    Error = ''
    while True:
        os.system('cls' if os.name=='nt' else 'clear')
        if Error != '':
            print Error
            Error = ''

        flItms = support_check(outputfile, DISK_OFFSET)
        flItms['outputfile'] = outputfile
        f = open(flItms['outputfile'], "r+b")
        print "[?] What sections would you like to change:"
        get_section_attributes(flItms)
        for i, section in enumerate(flItms['Sections']):
            print i+1, "Section:", section[0], "| SectionFlags:", hex(section[9])
        number = raw_input("Section number:")
        if number in exit_values:
            print "exiting"
            f.close()
            break
        try:
            number = int(number)
        except:
            Error = "Whoops, try again..."
            continue
        print "[-] You picked the", flItms['Sections'][number-1][0], "section."
        selection = raw_input("[?] Would you like to (A) change the section name or (B) the section flags? ")
        print "[-] You picked:", selection
        if selection.lower() == 'a':
            while True:
                newSectionName=raw_input("[?] Enter a new section name (less than 7 chars): ")
                if len(newSectionName) <= 7:
                    newSectionName = newSectionName + ((7 - len(newSectionName)) * "\x00")
                    break
            change_section_name(flItms, flItms['Sections'][number-1][0], newSectionName)
        if selection.lower() == 'b':
            attributeStore=set()
            Error_call = False
            error_msg = ''
            while True:
                os.system('cls' if os.name=='nt' else 'clear')
                if Error_call is True:
                    print error_msg
                    Error_call = False
                get_section_attributes(flItms)
                if attributeStore != set([]):
                    print "[!] Attributes to write:"
                    for attrib in attributeStore:
                        print "[*]", attrib
                print "=" * 25
                print "[*] Current attributes:"
                try:
                    print flItms['Sections'][number-1][0], "|" , hex(flItms['Sections'][number-1][9])
                    for attrib in flItms['FlagAttributes'][flItms['Sections'][number-1][0]]:
                        print "[-]", attrib
                except:
                    print "[!] No attributes assigned."
                print "=" * 25
                print "[*] Commands 'zero' out the flags, 'help', 'write', or ('exit', 'quit', 'q', 'done')"
                print "[*] Use 'write' to commit your changes or 'clear' to start over."
                attrib_select = raw_input("[?] Enter an attribute to add or type 'help' or 'exit': ")
                if attrib_select.lower() == 'help':
                    Error_call = True
                    error_msg = sectionflag_help
                elif attrib_select.lower() in exit_values:
                    break
                elif attrib_select.lower() == 'clear':
                    attributeStore = set() 
                elif attrib_select.lower() == 'write':
                    new_value = change_section_flags(flItms, flItms['Sections'][number-1], attributeStore)
                    flItms['Sections'][number-1][9] = new_value
                    attributeStore=set()
                elif attrib_select.lower() == 'zero':
                    print "This will zero out your selection. You can't go back.."
                    ans = raw_input("Continue? (y/n)")
                    if ans.lower()  != 'y':
                        break
                    new_value = change_section_flags(flItms, flItms['Sections'][number-1], set(['zero'],))
                    flItms['Sections'][number-1][9] = new_value
                else:
                    for each_attribute in [x.strip() for x in attrib_select.split(',')]:
                        #add to attribute store, check 1st if they exist:
                        found = False
                        try:
                            print each_attribute.upper(), flItms['FlagAttributes'][flItms['Sections'][number-1][0]]
                            for list_item in flItms['FlagAttributes'][flItms['Sections'][number-1][0]]:
                                if each_attribute in [x.strip() for x in list_item.split(',')]:
                                    error_msg = "[!] " + each_attribute + " already assigned, continuting.."
                                    Error_call = True
                                    found = True
                                    continue
                        except:
                            pass
                        for key, value in section_flags.iteritems():
                            if found is True:
                                break
                            for key1, value1 in value.iteritems():
                                if each_attribute.upper() == key1:
                                    attributeStore.add(each_attribute)
                                    print each_attribute, "added for writing"
                                    found = True
                        if found is False:
                            Error_call = True
                            error_msg = "[!] Attribute not found please try again."
        f.close()

    print "Writing to log_recomposer.txt"
    g = open("log_recomposer.txt",'a')
    g.write(FILE + '|' + md5_for_file(FILE) + '|')
    g.write(outputfile + '|' + md5_for_file(outputfile) + '\n')
    g.close()

def change_section_name(flItms, section, name="none"):
    print "[*] Changing Section " + section + " Name"
    f.seek(flItms['BeginSections'], 0)
    for _ in range(flItms['NumberOfSections']):
        currentPos = f.tell()
        sec_name = f.read(8)
        if section in sec_name:
            f.seek(currentPos)
            #must be less than 7
            f.write("." + name)
            return True
        else:
            f.seek(32, 1)
    return False


def find_cave(flItms, shellcode_length):
    """This function finds all code caves, allowing the user
    to pick the cave for injecting shellcode."""

    len_allshells = (shellcode_length, )
    SIZE_CAVE_TO_FIND = shellcode_length
    Tracking = 0
    count = 1
    caveTracker = []
    caveSpecs = []

    f.seek(0)

    while True:
        try:
            s = struct.unpack("<b", f.read(1))[0]
        except:
            break
        if s == 0:
            if count == 1:
                BeginCave = Tracking
            count += 1
        else:
            if count >= SIZE_CAVE_TO_FIND:
                caveSpecs.append(BeginCave)
                caveSpecs.append(Tracking)
                caveTracker.append(caveSpecs)
            count = 1
            caveSpecs = []

        Tracking += 1

    pickACave = {}
    
    section_injected = {}
    for section in flItms['Sections']:
        section_injected[section[0]] = False
    for i, caves in enumerate(caveTracker):
        i += 1
        countOfSections = 0
        for section in flItms['Sections']:
            sectionFound = False
            try:
                if caves[0] >= section[4] and \
                   caves[1] <= (section[3] + section[4]) and \
                   caves[1] - caves[0] >= SIZE_CAVE_TO_FIND:
                    if verbose is True:
                        print "Inserting code in this section:", section[0]
                        print '->Begin Cave', hex(caves[0])
                        print '->End of Cave', hex(caves[1])
                        print 'Size of Cave (int)', caves[1] - caves[0]
                        print 'SizeOfRawData', hex(section[3])
                        print 'PointerToRawData', hex(section[4])
                        print 'End of Raw Data:', hex(section[3] + section[4])
                        print '*' * 50
                    JMPtoCodeAddress = (section[2] + caves[0] - section[4] -
                                        5 - flItms['AddressOfEntryPoint'])
                    section_injected[section[0]] = True
                    sectionFound = True
                    pickACave[i] = [section[0], hex(caves[0]), hex(caves[1]),
                                    caves[1] - caves[0], hex(section[4]),
                                    hex(section[3] + section[4]), JMPtoCodeAddress]
                    break
            except:
                print "-End of File Found.."
                break
        
            JMPtoCodeAddress = (section[2] + caves[0] - section[4] -
                                5 - flItms['AddressOfEntryPoint'])
            try:
                pickACave[i] = ["None", hex(caves[0]), hex(caves[1]),
                                caves[1] - caves[0], "None",
                                "None", JMPtoCodeAddress]
            except:
                print "EOF"

        if sectionFound is False:
            if verbose is True:
                print "No section"
                print '->Begin Cave', hex(caves[0])
                print '->End of Cave', hex(caves[1])
                print 'Size of Cave (int)', caves[1] - caves[0]
                print '*' * 50

    
    for key, value in section_injected.iteritems():
        if value is False:
            print '\033[93m' + "[!] Warning,", key, "section hash is not changed!"
            print "[!] No caves available for nop injection." + '\033[0m'

    CavesPicked = {}

    for k, item in enumerate(len_allshells):
       
        for ref, details in pickACave.iteritems():
            
            if int(details[1], 16) < flItms['Sections'][0][2]:
                continue
            # write to code cave
            payload_size = details[3] / 8
            if payload_size < 2:
                payload_size = 5
            payload_size = random.randrange(1, payload_size)
            f.seek(0)
            write_point = int(details[1], 16) + ( ( details[3] - payload_size) / 2 )
            f.seek(write_point, 0)
            thenop =random.choice(nops)
            if thenop > 144:
                f.write(struct.pack('!H', thenop) * (payload_size / 2))
            else:
                f.write(struct.pack('!B', thenop) * (payload_size))

        
def change_section_flags(flItms, section, flagvalues):
    """
    Changes the user selected section to RWE for successful execution
    """
    print "[*] Changing Section " + section[0] + " Flags"
    sectionName = section[0]
    newSectionFlags = section[9]
    for item in flagvalues:
        if item == 'zero'.lower():
            newSectionFlags = 0x00000000
        found = False
        for key, value in section_flags.iteritems():
            if found is True:
                break
            for key1, value1 in value.iteritems():
                if item == key1:
                    if 'Group6' == key:
                        print key
                        newSectionFlags = value1
                    else:    
                        newSectionFlags += value1
                    found = True
                    break

        f.seek(flItms['BeginSections'], 0)
        for _ in range(flItms['NumberOfSections']):
            sec_name = f.read(8)
            if sectionName in sec_name:
                #print "found it"
                f.seek(28, 1)
                if newSectionFlags == 0:
                    f.write("\x00\x00\x00\x00")
                else:
                    f.write(struct.pack('<I', newSectionFlags))
            else:
                f.seek(32, 1)
    return newSectionFlags


def print_section_attr():
    """
    Prints the section attributes by calculating each type of section.
    """
    eachtypeofsection={}
    sectionAttrib = []
        
    for keyA, valueA in section_flags.iteritems():
        print keyA, valueA
        for keyA, valueB in valueA.iteritems():
            print keyA, valueB  


def support_check(filename, LocOfEntryinCode_Offset):
    """
    This function is for checking if the current exe/dll is
    supported by this program. Returns false if not supported,
    returns flItms if it is.
    """
    print "[*] Checking if binary is supported"
    flItms = {}
    flItms['supported'] = False
    global f
    f = open(filename, "rb")
    flItms['LocOfEntryinCode_Offset'] = LocOfEntryinCode_Offset
    if f.read(2) != "\x4d\x5a":
        print "%s not a PE File" % filename
        return False
    flItms = gather_file_info_win(flItms, filename, flItms['LocOfEntryinCode_Offset'])
    if flItms is False:
        return False
    if MachineTypes[hex(flItms['MachineType'])] not in supported_types:
        for item in flItms:
            print item + ':', flItms[item]
        print ("This program does not support this format: %s"
               % MachineTypes[hex(flItms['MachineType'])])
    else:
        flItms['supported'] = True
    
    f.close()

    if verbose is True:
        print_flItms(flItms)

    if flItms['supported'] is False:
        return False
    else:
        return flItms


def gather_file_info_win(flItms, filename, LocOfEntryinCode_Offset):
    """
    Gathers necessary PE header information to backdoor
    a file and returns a dict of file information called flItms
    """
    s = f.seek(int('3C', 16))
    print "[*] Gathering file info"
    flItms['filename'] = filename
    flItms['buffer'] = 0
    flItms['JMPtoCodeAddress'] = 0
    flItms['LocOfEntryinCode_Offset'] = LocOfEntryinCode_Offset
    flItms['dis_frm_pehdrs_sectble'] = 248
    flItms['pe_header_location'] = struct.unpack('<i', f.read(4))[0]
    # Start of COFF
    flItms['COFF_Start'] = flItms['pe_header_location'] + 4
    f.seek(flItms['COFF_Start'])
    flItms['MachineType'] = struct.unpack('<H', f.read(2))[0]
    for mactype, name in MachineTypes.iteritems():
        if int(mactype, 16) == flItms['MachineType']:
            if verbose is True:
                print 'MachineType is:', name
    #f.seek(flItms['ImportTableLocation'])
    #flItms['IATLocInCode'] = struct.unpack('<I', f.read(4))[0]
    f.seek(flItms['COFF_Start'] + 2, 0)
    flItms['NumberOfSections'] = struct.unpack('<H', f.read(2))[0]
    flItms['TimeDateStamp'] = struct.unpack('<I', f.read(4))[0]
    f.seek(flItms['COFF_Start'] + 16, 0)
    flItms['SizeOfOptionalHeader'] = struct.unpack('<H', f.read(2))[0]
    flItms['Characteristics'] = struct.unpack('<H', f.read(2))[0]
    #End of COFF
    flItms['OptionalHeader_start'] = flItms['COFF_Start'] + 20
    if flItms['SizeOfOptionalHeader']:
        #Begin Standard Fields section of Optional Header
        f.seek(flItms['OptionalHeader_start'])
        flItms['Magic'] = struct.unpack('<H', f.read(2))[0]
        flItms['MajorLinkerVersion'] = struct.unpack("!B", f.read(1))[0]
        flItms['MinorLinkerVersion'] = struct.unpack("!B", f.read(1))[0]
        flItms['SizeOfCode'] = struct.unpack("<I", f.read(4))[0]
        flItms['SizeOfInitializedData'] = struct.unpack("<I", f.read(4))[0]
        flItms['SizeOfUninitializedData'] = struct.unpack("<i",
                                                          f.read(4))[0]
        flItms['AddressOfEntryPoint'] = struct.unpack('<I', f.read(4))[0]
        flItms['BaseOfCode'] = struct.unpack('<i', f.read(4))[0]
        #print 'Magic', flItms['Magic']
        if flItms['Magic'] != int('20B', 16):
            #print 'Not 0x20B!'
            flItms['BaseOfData'] = struct.unpack('<i', f.read(4))[0]
        # End Standard Fields section of Optional Header
        # Begin Windows-Specific Fields of Optional Header
        if flItms['Magic'] == int('20B', 16):
            #print 'x64!'
            flItms['ImageBase'] = struct.unpack('<Q', f.read(8))[0]
        else:
            flItms['ImageBase'] = struct.unpack('<I', f.read(4))[0]
        #print 'flItms[ImageBase]', hex(flItms['ImageBase'])
        flItms['SectionAlignment'] = struct.unpack('<I', f.read(4))[0]
        flItms['FileAlignment'] = struct.unpack('<I', f.read(4))[0]
        flItms['MajorOperatingSystemVersion'] = struct.unpack('<H',
                                                              f.read(2))[0]
        flItms['MinorOperatingSystemVersion'] = struct.unpack('<H',
                                                              f.read(2))[0]
        flItms['MajorImageVersion'] = struct.unpack('<H', f.read(2))[0]
        flItms['MinorImageVersion'] = struct.unpack('<H', f.read(2))[0]
        flItms['MajorSubsystemVersion'] = struct.unpack('<H', f.read(2))[0]
        flItms['MinorSubsystemVersion'] = struct.unpack('<H', f.read(2))[0]
        flItms['Win32VersionValue'] = struct.unpack('<I', f.read(4))[0]
        flItms['SizeOfImageLoc'] = f.tell()
        flItms['SizeOfImage'] = struct.unpack('<I', f.read(4))[0]
        #print "size of img", flItms['SizeOfImage']
        flItms['SizeOfHeaders'] = struct.unpack('<I', f.read(4))[0]
        flItms['CheckSum'] = struct.unpack('<I', f.read(4))[0]
        flItms['Subsystem'] = struct.unpack('<H', f.read(2))[0]
        flItms['DllCharacteristics'] = struct.unpack('<H', f.read(2))[0]
        if flItms['Magic'] == int('20B', 16):
            flItms['SizeOfStackReserve'] = struct.unpack('<Q', f.read(8))[0]
            flItms['SizeOfStackCommit'] = struct.unpack('<Q', f.read(8))[0]
            flItms['SizeOfHeapReserve'] = struct.unpack('<Q', f.read(8))[0]
            flItms['SizeOfHeapCommit'] = struct.unpack('<Q', f.read(8))[0]

        else:
            flItms['SizeOfStackReserve'] = struct.unpack('<I', f.read(4))[0]
            flItms['SizeOfStackCommit'] = struct.unpack('<I', f.read(4))[0]
            flItms['SizeOfHeapReserve'] = struct.unpack('<I', f.read(4))[0]
            flItms['SizeOfHeapCommit'] = struct.unpack('<I', f.read(4))[0]
        flItms['LoaderFlags'] = struct.unpack('<I', f.read(4))[0]  # zero
        flItms['NumberofRvaAndSizes'] = struct.unpack('<I', f.read(4))[0]
        # End Windows-Specific Fields of Optional Header
        # Begin Data Directories of Optional Header
        flItms['ExportTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['ImportTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['ResourceTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['ExceptionTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['CertificateTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['BaseReLocationTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['Debug'] = struct.unpack('<Q', f.read(8))[0]
        flItms['Architecutre'] = struct.unpack('<Q', f.read(8))[0]  # zero
        flItms['GlobalPrt'] = struct.unpack('<Q', f.read(8))[0]
        flItms['TLS Table'] = struct.unpack('<Q', f.read(8))[0]
        flItms['LoadConfigTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['ImportTableLocation'] = f.tell()
        #print 'ImportTableLocation', hex(flItms['ImportTableLocation'])
        flItms['BoundImport'] = struct.unpack('<Q', f.read(8))[0]
        f.seek(flItms['ImportTableLocation'])
        flItms['IATLocInCode'] = struct.unpack('<I', f.read(4))[0]
        #print 'first IATLOCIN CODE', hex(flItms['IATLocInCode'])
        flItms['IATSize'] = struct.unpack('<I', f.read(4))[0]
        #print 'IATSize', hex(flItms['IATSize'])
        flItms['IAT'] = struct.unpack('<Q', f.read(8))[0]
        flItms['DelayImportDesc'] = struct.unpack('<Q', f.read(8))[0]
        flItms['CLRRuntimeHeader'] = struct.unpack('<Q', f.read(8))[0]
        flItms['Reserved'] = struct.unpack('<Q', f.read(8))[0]  # zero
        flItms['BeginSections'] = f.tell()

    flItms['Sections'] = []
    for section in range(flItms['NumberOfSections']):
        sectionValues = []
        sectionValues.append(f.read(8))
        # VirtualSize
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        # VirtualAddress
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        # SizeOfRawData
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        # PointerToRawData
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        # PointerToRelocations
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        # PointerToLinenumbers
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        # NumberOfRelocations
        sectionValues.append(struct.unpack('<H', f.read(2))[0])
        # NumberOfLinenumbers
        sectionValues.append(struct.unpack('<H', f.read(2))[0])
        # SectionFlags
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        flItms['Sections'].append(sectionValues)
 
    flItms['VirtualAddress'] = flItms['SizeOfImage']

    flItms['VrtStrtngPnt'] = (flItms['AddressOfEntryPoint'] +
                              flItms['ImageBase'])
    f.seek(flItms['IATLocInCode'])
    flItms['ImportTableALL'] = f.read(flItms['IATSize'])
    flItms['NewIATLoc'] = flItms['IATLocInCode'] + 40
    return flItms


def print_flItms(flItms):

    keys = flItms.keys()
    keys.sort()
    for item in keys:
        if type(flItms[item]) == int:
            print item + ':', hex(flItms[item])
        elif item == 'Sections':
            print "-" * 50
            for section in flItms['Sections']:
                print "Section Name", section[0]
                print "Virutal Size", hex(section[1])
                print "Virtual Address", hex(section[2])
                print "SizeOfRawData", hex(section[3])
                print "PointerToRawData", hex(section[4])
                print "PointerToRelocations", hex(section[5])
                print "PointerToLinenumbers", hex(section[6])
                print "NumberOfRelocations", hex(section[7])
                print "NumberOfLinenumbers", hex(section[8])
                print "SectionFlags", hex(section[9])
                print "-" * 50
        else:
            print item + ':', flItms[item]
    print "*" * 50, "END flItms"


def get_section_attributes(flItms):
    flItms['FlagAttributes'] = {}
    #print flItms['Sections']
    for section in flItms['Sections']:
        sectionTracker = []
        if len(hex(section[9])) != 10:
            section_value = '0x' + '0' * (8 - len(hex(section[9]).split('0x')[1])) + hex(section[9]).split('0x')[1]
        else:
            section_value = hex(section[9])
        for i, j in enumerate(section_value.split('0x')[1]):
            if j == '0':
                continue
            elif i == 0:
                groupValue = "Group8"
                #values = section_flags[groupValue].values()
                #results = get_values(combinations(values))
                #parse_attribs(groupValue, results, i, j)
                sectionTracker.append(parse_attribs(groupValue, i, j))
                #print results
            elif i == 1:
                groupValue = "Group7"
                #values = section_flags[groupValue].values()
                #results = get_values(combinations(values))
                #parse_attribs(groupValue, results, i, j)
                sectionTracker.append(parse_attribs(groupValue, i, j))
                #print results
            elif i == 2:
                groupValue = "Group6"
                #values = section_flags[groupValue].values()
                #results = get_values(combinations(values))
                #parse_attribs(groupValue, results, i, j)
                sectionTracker.append(parse_attribs(groupValue, i, j))
                #print results
            elif i == 3:
                groupValue = "Group5"
                #values = section_flags[groupValue].values()
                #results = get_values(combinations(values))
                #parse_attribs(groupValue, results, i, j)
                sectionTracker.append(parse_attribs(groupValue, i, j))
                
            elif i == 4:
                groupValue = "Group4"
                #values = section_flags[groupValue].values()
                #results = get_values(combinations(values))
                #parse_attribs(groupValue, results, i, j)
                sectionTracker.append(parse_attribs(groupValue, i, j))
                #print results
            elif i == 5:
                groupValue = "Group3"
                #values = section_flags[groupValue].values()
                #results = get_values(combinations(values))
                #parse_attribs(groupValue, results, i, j)
                sectionTracker.append(parse_attribs(groupValue, i, j))
                #print results
            elif i == 6:
                groupValue = "Group2"
                #values = section_flags[groupValue].values()
                #print "values", values
                
                #results = get_values(combinations(values))
                #parse_attribs(groupValue, results, i, j)
                sectionTracker.append(parse_attribs(groupValue, i, j))
                #print results
            elif i == 7:
                groupValue = "Group1"
                #print 6
                #values = section_flags[groupValue].values()
                #results = get_values(combinations(values))
                sectionTracker.append(parse_attribs(groupValue, i, j))
                #parse_attribs(groupValue, results, i, j)
                #print results
            flItms["FlagAttributes"][section[0]]=sectionTracker


def parse_attribs(groupValue, position, value):
    #print section_flags[groupValue], results, position, value
    #print groupValue
    MyValue = int('0x' + '0' * (position) + str(value) + '0' * (7 - position), 16)
    #print MyValue
    #continue here list attribs
    tempValue = 0
    FlagAttributes = []
    for key, value in sorted(section_flags[groupValue].iteritems(), key=operator.itemgetter(1), reverse=True):
        if value > MyValue:
            continue   
        if tempValue != 0 and value > tempValue:
            #print "Value Greater than MyValue"
            continue

        if tempValue > 0:
            if tempValue % value == 0:
                #print "tempValue, found value"
                #print "Flag", key
                FlagAttributes.append(key)
                break
        #print key, '\t', value
        tempValue = MyValue % value
        if tempValue == 0:
            #print "found value"
            #print "Flag", key
            FlagAttributes.append(key)
            break
        else:
            #print "Flag", key
            FlagAttributes.append(key)
            #print 'tempValue', tempValue

    return ", ".join(FlagAttributes)


if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-f", "--file", dest="FILE", action="store",
                      type="string",
                      help="File to backdoor")
    parser.add_option("-o", "--output-file", default="", dest="OUTPUT",
                      action="store", type="string",
                      help="The backdoor output file")
    
    parser.add_option("-O", "--disk_offset", default=0,
                      dest="DISK_OFFSET", type="int", action="store",
                      help="Starting point on disk offset, in bytes. "
                      "Some authors want to obfuscate their on disk offset "
                      "to avoid reverse engineering, if you find one of those "
                      "files use this flag, after you find the offset.")
  
    parser.add_option("-v", "--verbose", default=False, dest="VERBOSE",
                      action="store_true",
                      help="For debug information output.")
    parser.add_option("-m", "--manual", default=False, dest="MANUAL",
                      action="store_true", 
                      help="To change section headers names and flags")
    parser.add_option("-a", "--auto", default=False, dest="AUTO",
                      action="store_true",
                      help="Randomly change section header names and flags")

    (options, args) = parser.parse_args()
    verbose = options.VERBOSE

    if not options.FILE:
        parser.print_help()
        sys.exit(1)

    if options.MANUAL is True:
        change_binary_workflow(options.FILE, options.OUTPUT, options.DISK_OFFSET)
        sys.exit(0)
    if options.AUTO is True:
        randomly_change_file(options.FILE, options.DISK_OFFSET)
        sys.exit(0)
    parser.print_help()
    sys.exit(1)