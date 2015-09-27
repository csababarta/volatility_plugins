# 
# This plugin is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# This plugin is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Csaba Barta
@license:      GNU General Public License 2.0
@contact:      csaba.barta@gmail.com
"""

import volatility.plugins.common as common
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.obj as obj
import struct
import binascii
import re
import volatility.constants
import csv
import sys

REASONSCODES = {
    0x00000001: 'Data in one or more named data streams for the file was overwritten.',
    0x00000002: 'The file or directory was added to.',
    0x00000004: 'The file or directory was truncated.',
    0x00000010: 'Data in one or more named data streams for the file was overwritten.',
    0x00000020: 'One or more named data streams for the file were added to.',
    0x00000040: 'One or more named data streams for the file was truncated.',
    0x00000100: 'The file or directory was created for the first time.',
    0x00000200: 'The file or directory was deleted.',
    0x00000400: "The user made a change to the file's or directory's extended attributes. These NTFS attributes are not accessible to Windows-based applications.",
    0x00000800: 'A change was made in the access rights to the file or directory.',
    0x00001000: 'The file or directory was renamed, and the file name in this structure is the previous name.',
    0x00002000: 'The file or directory was renamed, and the file name in this structure is the new name.',
    0x00004000: 'A user changed the FILE_ATTRIBUTE_NOT_CONTENT_INDEXED attribute. That is, the user changed the file or directory from one that can be content indexed to one that cannot, or vice versa.',
    0x00008000: 'A user has either changed one or more file or directory attributes or one or more time stamps.',
    0x00010000: 'An NTFS hard link was added to or removed from the file or directory',
    0x00020000: 'The compression state of the file or directory was changed from or to compressed.',
    0x00040000: 'The file or directory was encrypted or decrypted.',
    0x00080000: 'The object identifier of the file or directory was changed.',
    0x00100000: 'The reparse point contained in the file or directory was changed, or a reparse point was added to or deleted from the file or directory.',
    0x00200000: 'A named stream has been added to or removed from the file, or a named stream has been renamed.',
    0x80000000: 'The file or directory was closed.',
}

SOURCES = {
    0x00000002 : 'USN_SOURCE_AUXILIARY_DATA',
    0x00000001 : 'USN_SOURCE_DATA_MANAGEMENT',
    0x00000004 : 'USN_SOURCE_REPLICATION_MANAGEMENT'
  }

ATTRIBUTES = {
    1:'FILE_ATTRIBUTE_READONLY',
    2:'FILE_ATTRIBUTE_HIDDEN',
    4:'FILE_ATTRIBUTE_SYSTEM',
    16:'FILE_ATTRIBUTE_DIRECTORY',
    32:'FILE_ATTRIBUTE_ARCHIVE',
    64:'FILE_ATTRIBUTE_DEVICE',
    128:'FILE_ATTRIBUTE_NORMAL',
    256:'FILE_ATTRIBUTE_TEMPORARY',
    512:'FILE_ATTRIBUTE_SPARSE_FILE',
    1024:'FILE_ATTRIBUTE_REPARSE_POINT',
    2048:'FILE_ATTRIBUTE_COMPRESSED',
    4096:'FILE_ATTRIBUTE_OFFLINE',
    8192:'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED',
    16384:'FILE_ATTRIBUTE_ENCRYPTED',
    65536:'FILE_ATTRIBUTE_VIRTUAL'
}

INDX_STRUCTS = {
    'INDX_HEADER': [ None, {
        'Magic' : [0x00, ['String', dict(encoding='ascii', length=4)]],
        'OffsetUpdateSequenceArray': [0x04, ['unsigned short']],
        'SizeUpdateSequenceArray'  : [0x06, ['unsigned short']],
        'LogfileSequenceNumber': [0x08, ['unsigned long long']],
        'VirtualClusterNumber': [0x10, ['unsigned long long']],
        'OffsetIndexEntryHeader': [0x18, ['unsigned int']],
        'OffsetEndFinalEntry': [0x1c, ['unsigned int']],
        'AllocatedSizeOfEntries': [0x20, ['unsigned int']],
        'IndexTypeFlag': [0x24, ['insigned char']],
        'Padding1': [0x25, ['array', 3, ['unsigned char']]],
        'USN': [0x28, ['unsigned short']],
        'UpdateSequenceArray': [0x2a, ['array', 4, ['unsigned int']]],
        'Padding2': [0x3a, ['array', 4, ['unsigned char']]]
    }],

    'INDX_ENTRY_HEADER': [ None, {
        'MFT': [0x00, ['FILE_REFERENCE']],
        'EntryLength': [0x08, ['unsigned short']],
        'StreamLength': [0x0a, ['unsigned short']],
        'ListingFlag': [0x0c, ['unsigned char']],
        'Padding': [0x0d, ['array', 3, ['unsigned char']]]
    }]
}

class INDX_HEADER(obj.CType):
    @property
    def isValid(self):
        # print self.AllocatedSizeOfEntries
        # print (self.OffsetEndFinalEntry + 0x1a)
        # print self.Padding1[0].v()
        if self.Padding1[0].v() == 0x00 and \
           self.Padding1[1].v() == 0x00 and \
           self.Padding1[2].v() == 0x00 and \
           self.AllocatedSizeOfEntries < 4096 and \
           (self.OffsetEndFinalEntry + 0x1a) < 4096 and \
           self.Padding2[0].v() == 0x00 and \
           self.Padding2[1].v() == 0x00 and \
           self.Padding2[2].v() == 0x00:
            return True
        else:
            return False
    
    def __str__(self):
        return "INDX_HEADER"

class INDX_ENTRY_HEADER(obj.CType):
    @property
    def isValid(self):
        if self.StreamLength < self.EntryLength and \
           self.StreamLength <= 1024 and \
           self.StreamLength >= 0x44 and \
           self.Padding[0].v() == 0x00 and \
           self.Padding[1].v() == 0x00 and \
           self.Padding[2].v() == 0x00:
            return True
        else:
            return False
        
    def __str__(self):
        return "INDX_ENTRY_HEADER"

class INDX_STRUCT(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows'}
    def modification(self, profile):
        profile.object_classes.update({
            'INDX_HEADER' : INDX_HEADER,
            'INDX_ENTRY_HEADER' : INDX_ENTRY_HEADER,
        })
        profile.vtypes.update(INDX_STRUCTS)

class INDXScanner(scan.BaseScanner):
    checks = [ ]
    overlap = 0x40

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("INDXRegExCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self) 

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset

class INDXRegExCheck(scan.ScannerCheck):
    """ Checks for multiple strings per page """
    
    regexs = []

    def __init__(self, address_space, needles = None):
        scan.ScannerCheck.__init__(self, address_space)
        if not needles:
            needles = []
        self.needles = needles
        self.maxlen = 0x40
        for needle in needles:
            r = re.compile(needle)
            self.regexs.append(re.compile(needle))
        if not self.maxlen:
            raise RuntimeError("No needles of any length were found for the " + self.__class__.__name__)

    def check(self, offset):
        usn_buff = self.address_space.read(offset, 4095)
        for regex in self.regexs:
            if regex.match(usn_buff) != None:
                return True
        return False

    def skip(self, data, offset):
        for regex in self.regexs:
            ih = regex.search(data)
            if ih == None:
                return len(data) - offset
            else:
                return ih.start()


class INDX(common.AbstractWindowsCommand):
    """ Scans for and parses potential INDX entries """
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')
        scanner = INDXScanner(needles = ['INDX\('])
        
        # Carve INDX Headers
        for offset in scanner.scan(address_space):
            indx_entries = []
            indx_header_buff = address_space.zread(offset, 0x40)
            bufferas = addrspace.BufferAddressSpace(self._config, data = indx_header_buff)
            indx_header = obj.Object('INDX_HEADER', vm = bufferas,
                               offset = 0)
            
            # Check the headers
            if indx_header.isValid:
                indx_buff = address_space.zread(offset+40, 4096)
                indx_bufferas = addrspace.BufferAddressSpace(self._config, data = indx_buff)
                o = 0
                # Iterate through the entries
                while o < indx_header.AllocatedSizeOfEntries:
                    indx_entry_header = obj.Object('INDX_ENTRY_HEADER', vm=indx_bufferas,
                                                   offset=o)
                    
                    # Check the entry headers
                    if indx_entry_header.isValid:
                        if len(indx_bufferas.data[o+16:o+16+indx_entry_header.StreamLength]) == indx_entry_header.StreamLength:
                            indx_entry = obj.Object('FILE_NAME', vm=indx_bufferas, offset=o+16)
                            if indx_entry.is_valid():
                                indx_entries.append([indx_entry_header,indx_entry])
                        o = o + indx_entry_header.EntryLength
                    else:
                        o += 1
            yield offset, indx_header, indx_entries

    def render_text(self, outfd, data):
        for offset, indx_header, indx_entries in data:
            print "INDX Header Offset: " + str(offset)
            for h,e in indx_entries:
                print str(e)
            print "*" * 80
    
    def render_body(self, outfd, data):
        for offset, indx_header, indx_entries in data:
            for h,e in indx_entries:
                print "{0} (Offset: 0x{1:x})|{2}|{3}|0|0|{4}|{5}|{6}|{7}|{8}".format(
                    e.get_name(),
                    offset,
                    h.MFT.RecordNumber,
                    e.get_type_short(),
                    e.RealFileSize,
                    e.FileAccessedTime.v(),
                    e.ModifiedTime.v(),
                    e.MFTAlteredTime.v(),
                    e.CreationTime.v())