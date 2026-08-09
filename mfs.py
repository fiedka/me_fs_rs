# slightly modified, taken from
# <https://reverseengineering.stackexchange.com/questions/23324/intel-me-partitions-effs-and-fcrs>

import sys

#litte-endian integer readers
def read_leuint8(file):
    data = file.read(1)
    return data[0]

def read_leuint16(file):
    data = file.read(2)
    return data[0] | (data[1] << 8)

def read_leuint24(file):
    data = file.read(3)
    return data[0] | (data[1] << 8) | (data[2] << 16)

def read_leuint32(file):
    data = file.read(4)
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)


class MEFileSystemFileMetadataStateMachine:
    """ 
    MEFileSystemFileMetadata:

    Files in MFS have internal metadata entries.  Each file begins with a metadata 
    record, observed values are:
        0xa# <bytes ahead until next metadata>  <0x01> <next meta block num> <0x00>
        0xb# <blocks ahead until next metadata> <0x01> <next meta block num> <0x00>
        0x8# <bytes remaining in file (including this metadata)>

    where
        #                   --  is the file number within the block.  This is the 
                                target for the fno field of the allocation table 
                                entry.
        <bytes ahead...>    --  the number of bytes to move ahead to find the next 
                                metadata record (including this metadata).
        <next meta block...>--  the 0x100-byte block number where the next metadata 
                                record is to be found. This value should be looked 
                                up through the data-page's block-indirection table.
        <blocks ahead...>   --  the number of 0x100 byte blocks to move ahead to 
                                find the next metadata record (including this 
                                metadata).
        <bytes remaining...>--  pretty straight-forward.

    So, 0x8# metadata are file-end records; 0xa# are short-range references; and 
    0xb# are longer range references.  This metadata chain provides unamiguous file 
    numbers within the blocks, and since they're put at the block start of any 
    block that contains a file-start, it's easy to pick up from an allocation table 
    reference.

    Note: 0x8# records don't point to the next metadata block, so we may have to 
    consume file-end padding (0xff until the next multiple of 0x10) if we get an 
    intermediate 0x8# metadata while searching for our target file.
    """
    STATE_NEED_META = 0
    STATE_NEED_SKIP_DATA = 1
    STATE_NEED_FILE_DATA = 2
    STATE_COMPLETE = 3

    def __init__(self, file_no, file_len):
        self.file_no = file_no

        self.state = MEFileSystemFileMetadataStateMachine.STATE_NEED_META
        self.bytes_needed = 1
        self.byte_offset = 0
        self.cur_meta = bytearray(5)
        self.file_data = bytearray(file_len)
        self.file_filled = 0
        self.found_fileno = False

        self.work_buf = self.cur_meta

    def is_complete(self):
        return self.state == self.STATE_COMPLETE

    def get_file_data(self):
        return self.file_data

    def get_bytes_needed(self):
        return self.bytes_needed

    #returns the number of bytes consumed
    def add_bytes(self,
        bytes,
        start_index,
        data_len=None,
        log = None
    ):
        """
        supplies data to satisfy the state-machine's need for data as reported
        via get_bytes_needed().

        bytes       -- the buffer containing the bytes to be fed in
        start_index -- the start location of the bytes within the buffer
        data_len    -- number of bytes in the array, starting at start_index.
                       if None, then len(bytes) - start_index is assumed

        sm = MEFileSystemFileMetadataStateMachine(file_no, file_len)
        while not sm.is_complete():
            bytes_read = sm.add_bytes(
                bytes=me_file.read(sm.get_bytes_needed()), 
                start_index=0,    
                data_len=None, #shorthand for len(bytes)-start_index
                log=log
            )
        """

        # shuffling data from potentially multiple calls to fill the data
        # request from the state machine (get_bytes_needed)
        data_len = len(bytes) - start_index if data_len is None else data_len

        if data_len == 0:
            # nothing to do
            log.write("no\n")
            return 0

        # take the min of what's available and what we need
        to_copy = data_len if data_len < self.bytes_needed else self.bytes_needed

        bo = self.byte_offset
        if self.work_buf:
            self.work_buf[bo:(bo+to_copy)] = bytes[start_index:(start_index+to_copy)]
            self.byte_offset = self.byte_offset + to_copy
        self.bytes_needed = self.bytes_needed - to_copy

        # if we don't have enough to process, return so they can feed more
        if self.bytes_needed > 0:
            log.write("ret\n")
            return to_copy

        # we only make it this far once we've got the full bytes_needed data
        meta_type = self.cur_meta[0] & 0xf0
        log.write(f"metadata type: 0x{meta_type:02x} @ {bo:08x}\n")
        if self.state == self.STATE_NEED_META:
            if self.byte_offset == 1:
                if meta_type in [0xa0, 0xb0]:
                    self.bytes_needed = 4
                else:
                    self.bytes_needed = 1
            else:
                # Have we found the file number we seek yet?
                if self.found_fileno or (self.file_no == self.cur_meta[0] & 0x0f):
                    self.found_fileno = True
                    self.state = self.STATE_NEED_FILE_DATA
                    self.work_buf = self.file_data
                    self.byte_offset = self.file_filled
                else:
                    self.state = self.STATE_NEED_SKIP_DATA
                    self.work_buf = None
                    self.byte_offset = 0

                # determine the data required based on metadata type, and
                # whether we're skipping (so need to eat EOF padding on type
                # 0x8# entries) or whether we're copying out file data.
                if meta_type == 0x80:
                    if self.state == self.STATE_NEED_SKIP_DATA:
                        # if we're skipping a 0x8# entry, we need to eat EOF padding too
                        padding = (0x10 - (self.cur_meta[1] & 0xf)) & 0xf
                        # remove header len, too
                        self.bytes_needed = padding + self.cur_meta[1] - 2
                    else:
                        # remove header len
                        self.bytes_needed = self.cur_meta[1] - 2
                elif meta_type == 0xa0:
                    # remove header len
                    self.bytes_needed = self.cur_meta[1] - 5
                elif meta_type == 0xb0:
                    # remove header len
                    self.bytes_needed = self.cur_meta[1] * 0x100 - 5
                else:
                    if log:
                        log.write("metadata type unknown: 0x%02x\n" % self.cur_meta[0])
                    return None

        # recall: this is the state just *completed*
        elif self.state == self.STATE_NEED_SKIP_DATA:
            self.state = self.STATE_NEED_META
            self.work_buf = self.cur_meta
            self.byte_offset = 0
            self.bytes_needed = 1

        # recall: this is the state just *completed*
        elif self.state == self.STATE_NEED_FILE_DATA:
            self.file_filled = self.byte_offset
            self.state = self.STATE_NEED_META
            self.work_buf = self.cur_meta
            self.byte_offset = 0
            if meta_type == 0x80:
                # just completed a file-end record...we're done.
                self.bytes_needed = 0
                self.state = self.STATE_COMPLETE
            elif meta_type in [0xa0, 0xb0]:
                self.bytes_needed = 1
            else:
                if log:
                    log.write("metadata type unknown: 0x%02x\n" % self.cur_meta[0])
                return None

        elif self.state == self.STATE_COMPLETE: #can't leave this state
            pass

        else:
            if log:
                log.write("Bad state-machine state: %d\n" % self.state)

        #recurse to consume as much as we can, for easier calling convention
        if to_copy < data_len:
            return  to_copy + add_bytes(bytes, start_index+to_copy, data_len-to_copy)

        #else, return what we consumed
        return to_copy


def read_me_fs_file(file_no, file_len, me_file, log = sys.stdout):
    sm = MEFileSystemFileMetadataStateMachine(file_no, file_len)

    log.write("read file with fno %d\n" % file_no)
    while not sm.is_complete():
        res = sm.add_bytes(
            bytes=me_file.read(sm.get_bytes_needed()), 
            start_index=0,    
            data_len=None, #shorthand for len(bytes)-start_index
            log=log
        )
        if not res:
            log.write("Aborting file read.\n")
            break

    return sm.get_file_data()

class MEFileSystemDataHeader:
    """
    Data Page Header: (Top of a 0x4000-byte data page in the MFS)
           0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
     00 | pgno|     pgflags     | 0x00| 0x00| 0x00| 0x00| mystery bits                                  | 
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
     10 | freed_flags...                                                                                |
        +-----------------------------------------------------------------------------------------------+
    ... | ...                                                                                           |
        +-----------------------------------------------------------------------------------------------+
     80 | ...                                                                                           |
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
     90 | block indirection table...                                                                    |
        +-----------------------------------------------------------------------------------------------+
    ... | ...                                                                                           |
        +-----------------------------------------------------------------------------------------------+
     c0 | ...                                                                                           |
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
     d0+| (file data follows)                                                                           |
        +-----------------------------------------------------------------------------------------------+

    pgno       -- page identifier within the MFS.  All MFS page headers 
                  have this field, be they AT or Data.
    pgflags    -- have seen 0x78 0xfe 0xff for AT header. Data pages have
                  had this or 0x78 0xfc 0xff.
    (zeros)    -- a useless value for flash...must be part of the signature
                  of the header?  Or reserved region for later version of
                  the format.
    myst_bits  -- TBD
    freed_flags-- each bit marks whether a written 0x10-byte chunk is no 
                  longer required.  Bits exist for the header chunks, as
                  well as the chunks for file data.  lsb of the first byte
                  corresponds to the first chunk of the header. 0=freed.
    blk_itab   -- translates ATFileEntry's okey value into a block offset 
                  within the data page.  offset = blk_itab[okey] * 0x100.
                  This is the location from which to begin the search. Note
                  that an offset of 0 must still respect that the page
                  header consumes bytes [0x00, 0xd0) for the search.
    (filedata) -- File are padded with 0xff at the end. Note files
                  have internal metadata.  See routines above.
    """

    def __init__(self, page_no, flags, bytes_00000000, myst_bits, freed_flags, blk_itab):
        self.page_no = page_no
        self.flags = flags
        self.zeros_good = bytes_00000000 == b'\x00\x00\x00\x00'
        self.myst_bits = myst_bits
        self.freed_flags = freed_flags
        self.blk_itab = blk_itab

    def debug_print(self, log = sys.stdout):
        log.write("Debug Print of MEFileSystemDataHeader %x:\n" % id(self))
        if self.page_no != 0xff:
            log.write("  page no: 0x%x\n" % self.page_no)
            log.write("  flags: 0x%06x\n" % self.flags)
            log.write("  zeros good: %s\n" % str(self.zeros_good))
            log.write("  mystery bits: %s\n" % " ".join("%02x"%x for x in self.myst_bits))
            log.write("  freed_flags: %s\n" % "".join("%02x"%x for x in self.freed_flags))
            log.write("  block ind. tab.: [%s]\n" % " ".join("%02x"%x for x in self.blk_itab))
        else:
            log.write("  (empty)\n")


class MEFileSystemATEntry:
    """
    Allocation Table Entry:
        0     1     2     3     4     5     6     7     8     9     a     
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
     00 |state| flgs|    identifier   | type|  filelen  | pgid| okey| fno |
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+

    state      -- status of the entry: 0xdc=present; 
                  0xc8=overwritten(i.e., there will be another entry below)
    flags      -- has value 0xf0 in every example...so hard to tell.
    identifier -- 3-byte identifier...seem to be a preference for ASCII,
                  but there are counterexamples
    type       -- no idea...maybe permissions?  Observed values:
                  0x00, 0x0a, 0x0c, 0x0d, 0x0e, 0x18, 0x1a
    filelen    -- 16-bit, little endian.  actual content seems to be a few
                  bytes more...might just be pollution of the structures
                  used to write the file.
    pgid       -- the pgno for the MEFileSystemDataHeader that holds the 
                  data.  The ATHeader is numbered 0, each data page seems
                  to get sequentially numbered in my examples, though that 
                  could change with more use. 0xff indicates "not
                  yet used / nonumber assigned" --- a fact that hints page
                  numbers aren't guaranteed to be sequentially
    okey       -- key for indexing the block_indirection table of the
                  MEFileSystemDataHeader holding this file's content, to 
                  find the right 0x100 byte block from which to start the
                  file search according to the 'fno' field.
    fno        -- file number within the block-offset determined from okey. 
                  This is to be looked up using the metadata *within* the 
                  file data of the data pages.  See 
                  MEFileSystemFileMetadataStateMachine above
    """
    def __init__(self, state, flags, identifier, type, filelen, pgid, okey, fno):
        self.state = state
        self.flags = flags
        self.identifier = identifier
        self.type = type
        self.filelen = filelen
        self.pgid = pgid
        self.okey = okey
        self.fno = fno

    def debug_print(self, log = sys.stdout):
        log.write("%15s len=0x%04x [pg=0x%02x k=0x%02x f=0x%02x] ty=0x%02x st=0x%02x, fg=0x%02x" % (str(self.identifier), self.filelen, self.pgid, self.okey, self.fno, self.type, self.state, self.flags))

class MEFileSystemATHeader:
    """
    Allocation Table Header:
           0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
     00 | pgno|      flags      | 0x00| 0x00| 0x00| 0x00|"MFS\0"                |bitfields?             | 
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
     10 | bitfields?            |
        +-----+-----+-----+-----+

    pgno       -- page identifier within the MFS.  All MFS page headers 
                  have this field, be they AT or Data.
    flags      -- have seen 0x78 0xfe 0xff for AT header. Data pages have
                  had this or 0x78 0xfc 0xff.
    (zeros)    -- a useless value for flash...must be part of the signature
                  of the header?  Or reserved region for later version of
                  the format.
    "MFS\0"    -- ASCIIZ signature for the MFS AT Header
    bitfields  -- 64 bits of apparent bitfields
    """

    max_files = int((0x4000 - 0x14) / 11) #page size, less the header, divided by file entry size

    def __init__(self, page_no, flags, bytes_00000000, sig, bitfields): 
        self.page_no = page_no
        self.flags = flags
        self.zeros_good = bytes_00000000 == b'\x00\x00\x00\x00'
        self.sig_good = sig == b'MFS\x00'
        self.bitfields = bitfields

    def debug_print(self, log = sys.stdout):
        log.write("Debug Print of MEFileSystemATHeader %x:\n" % id(self))
        log.write("  page no: 0x%x\n" % self.page_no)
        log.write("  flags: 0x%06x\n" % self.flags)
        log.write("  zeros good: %s\n" % str(self.zeros_good))
        log.write("  sig good: %s\n" % str(self.sig_good))
        log.write("  bitfields: %s\n" % " ".join("%02x"%x for x in self.bitfields))

class MEFileSystemAT:
    """
    Allocation Table (a 0x4000-byte page in the MFS):
           0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
     00 | Allocation Table Header...                                                                    |             
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
     10 |...                    | File Entry                                                      |FE...|
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
     ...|...                                                                                            |             
        +-----------------------------------------------------------------------------------+-----+-----+
    3fe0|...                                                                                |File Ent...|            
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
    3ff0|...                                                  |Padding                                  |             
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
    """

    def __init__(self, header, entry_list):
        self.header = header
        self.entry_list = entry_list

    def debug_print(self, log = sys.stdout):
        log.write("Debug Print of MEFileSystemAT %x:\n" % id(self))
        self.header.debug_print(log)

        log.write("File entries:\n")
        for ent in self.entry_list:
            if(ent):
                log.write("  ")
                ent.debug_print(log)
                log.write("\n")

class MEFileSystem:
    """
    MFS Partition: (Making the assumption the AT is the first page)
         +------------------------------------+
    0000 | Allocation Table                   |
         +------------------------------------+
    4000 | Data Page                          |
         +------------------------------------+
    8000 | Data Page                          |
         +------------------------------------+
    c000 | Data Page                          |
         +------------------------------------+
    ...  |...                                 |
         +------------------------------------+
    """

    def __init__(self, allocation_table, data_page_list):
        self.allocation_table = allocation_table
        self.data_page_list = data_page_list

    def debug_print(self, log = sys.stdout):
        log.write("Debug Print of MEFileSystem %x:\n" % id(self))
        self.allocation_table.debug_print(log)

        for page in self.data_page_list:
            if(page):
                page.debug_print(log)
            else:
                log.write("(Not parsed)\n")

def parse_me_fs_at_entry(me_file, log = sys.stdout):
    return MEFileSystemATEntry(
        state = read_leuint8(me_file),
        flags = read_leuint8(me_file),
        identifier = me_file.read(3),
        type = read_leuint8(me_file),
        filelen = read_leuint16(me_file),
        pgid = read_leuint8(me_file),
        okey = read_leuint8(me_file),
        fno = read_leuint8(me_file))

def parse_me_fs_at_header(me_file, log = sys.stdout):
    return MEFileSystemATHeader(
        page_no = read_leuint8(me_file),
        flags = read_leuint24(me_file),
        bytes_00000000 = me_file.read(4),
        sig = me_file.read(4),
        bitfields = me_file.read(8))

def parse_me_fs_at(me_file, log = sys.stdout):
    hdr = parse_me_fs_at_header(me_file, log)

    entry_list = [None] * MEFileSystemATHeader.max_files
    for i in range(MEFileSystemATHeader.max_files):
        ent = parse_me_fs_at_entry(me_file, log)
        if ent.state == 0xff:
            break
        entry_list[i] = ent

    return MEFileSystemAT(hdr, entry_list)


def parse_me_fs_data_header(me_file, log = sys.stdout):
    return MEFileSystemDataHeader(
        page_no = read_leuint8(me_file),
        flags = read_leuint24(me_file),
        bytes_00000000 = me_file.read(4),
        myst_bits = me_file.read(0x8),
        freed_flags = me_file.read(0x80),
        blk_itab = me_file.read(0x40))

def parse_me_fs(length, me_file, log = sys.stdout):
    """
    ARGS:
       length -- length in bytes of the ME partition holding the MFS/MFSB data
       me_file -- a file handle whose present position is the start of the MFS(B) partition
       log -- if there is diagnostic output, put it here

    RETURNS:
       an MEFileSystem instance populated with the allocation table and data-page headers
    """

    total_pages = int(length/0x4000)
    start_offset = me_file.tell()

    #NOTE: I'm presuming the allocation table is the first page...
    #that might not be reliable...
    at = parse_me_fs_at(me_file, log)

    data_pages = [None] * (total_pages-1)
    for page in range(0, total_pages-1):
        me_file.seek(start_offset + 0x4000 * (page+1))
        data_pages[page] = parse_me_fs_data_header(me_file, log)

    return MEFileSystem(
        allocation_table=at, 
        data_page_list = data_pages)


def get_mfs_file(mefs, me_file, id, log = sys.stdout):
    """
    Example of how to use the MEFileSystem structures to retrieve
    MFS and MFSB files.

    ARGS:
        mefs -- a MEFileSystem instance parsed from mfs_data
        me_file -- a filehandle containing the ME image
        id -- a 3-byte byte array with the file identifier
        log -- if there is diagnostic output, put it here

    RETURNS:
        an array containing [state, The data from the corresponding file].
        else None if the file identifier does not exist within the data.

    Example driver, given the known offset and size for a MFS partition:
        MFS_LENGTH = 0x40000 #typical size
        mefs = parse_me_fs(MFS_LENGTH, spi_image_file)
        result_tuple = get_mfs_file(mefs, spi_image_file, MFS_OFFSET, b'UKS')
        if result_tuple:
            print("State: %x, data: %s\n" % tuple(result_tuple))
    """

    # Find the file identifer in the Allocation Table
    best_ent = None
    for ent in mefs.allocation_table.entry_list:
        if ent and ent.identifier == id:
            best_ent = ent

            if ent.state == 0xdc:
                # got a current entry
                break;

            log.write("Error: found an item w/ state %02x...continuing\n" % ent.state)

    # if found, lookup which data page matches the entry's pgid value
    if best_ent:
        for list_idx in range(len(mefs.data_page_list)):
            page = mefs.data_page_list[list_idx]
            if page.page_no == best_ent.pgid:
                # we found the right data page, so start the file search
                search_start = page.blk_itab[best_ent.okey] * 0x100
                # d0 to skip over the datapage header if we're in the first block
                search_start = 0xd0 if search_start == 0 else search_start

                # In the following lines:
                #
                #  The multiple of 0x4000 selects the data offset that goes with list_idx
                #  since the parsed data-page list is in the same order as found in the file.
                #
                #  Because mefs.data_page_list doesn't include the allocation table page, we +1 
                #  to the index before multiplying.  The result is a set of offsets into the MFS data
                #  bounding the file search
                ##
                offset = 0x4000 * (list_idx+1) + search_start

                log.write("file offset %08x\n" % offset)

                me_file.seek(offset)
                data = read_me_fs_file(best_ent.fno, best_ent.filelen, me_file, log)
                if data:
                    return [best_ent.state, data]

    return None


if __name__ == "__main__":
    with open("image.bin", "rb") as spi_image_file:
        MFS_LENGTH = 0x40000 #typical size
        MFS_LENGTH = 0xdc000 # real size
        mefs = parse_me_fs(MFS_LENGTH, spi_image_file)

        # Dump the allocation table
        mefs.allocation_table.debug_print()
        print("")

        fnum = 92
        file = mefs.allocation_table.entry_list[fnum]
        first_file = file.identifier
        print("looking up file", fnum, first_file)
        result_tuple = get_mfs_file(mefs, spi_image_file, first_file)
        if result_tuple:
            [state, data] = result_tuple
            print(f"State: {state:x}, data: {data.hex(':')}\n")
