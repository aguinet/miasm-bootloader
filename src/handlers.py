#!/usr/bin/python2

import logging
import struct
import hexdump

from miasm2.analysis.binary import Container
from miasm2.analysis.machine import Machine
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE, EXCEPT_INT_XX

from helpers import get_xh, set_xh, get_xl, set_xl, set_16bit_reg
from disk import SECTOR_LEN
import async_kb

log = logging.getLogger("BIOS")

def log_hex(data):
    for l in hexdump.dumpgen(data):
        log.debug(l)

def func(ft, n):
    def dec(func):
        ft.register(n, func)
        return func
    return dec

class FuncTable(object):
    def __init__(self, name):
        self.__table = dict()
        self.__name = name

    @property
    def name(self):
        return self.__name

    def register(self, n, f):
        if (n in self.__table):
            raise ValueError("%s: function index %d already registered!" % (self.name, n))
        self.__table[n] = f

    def __call__(self, n, *args, **kwargs):
        f = self.__table.get(n, None)
        if f is None:
            raise NotImplementedError("%s: unknown function code 0x%x" % (self.name, n))
        return f(*args, **kwargs)

###################
###### DISK #######
###################

# For reference, from http://www.ctyme.com/intr/rb-0606.htm#Table234
# Values for disk operation status (meaning of return value AH):
# 00h    successful completion
# 01h    invalid function in AH or invalid parameter
# 02h    address mark not found
# 03h    disk write-protected
# 04h    sector not found/read error
# 05h    reset failed (hard disk)
# 05h    data did not verify correctly (TI Professional PC)
# 06h    disk changed (floppy)
# 07h    drive parameter activity failed (hard disk)
# 08h    DMA overrun
# 09h    data boundary error (attempted DMA across 64K boundary or >80h sectors)
# 0Ah    bad sector detected (hard disk)
# 0Bh    bad track detected (hard disk)
# 0Ch    unsupported track or invalid media
# 0Dh    invalid number of sectors on format (PS/2 hard disk)
# 0Eh    control data address mark detected (hard disk)
# 0Fh    DMA arbitration level out of range (hard disk)
# 10h    uncorrectable CRC or ECC error on read
# 11h    data ECC corrected (hard disk)
# 20h    controller failure
# 31h    no media in drive (IBM/MS INT 13 extensions)
# 32h    incorrect drive type stored in CMOS (Compaq)
# 40h    seek failed
# 80h    timeout (not ready)
# AAh    drive not ready (hard disk)
# B0h    volume not locked in drive (INT 13 extensions)
# B1h    volume locked in drive (INT 13 extensions)
# B2h    volume not removable (INT 13 extensions)
# B3h    volume in use (INT 13 extensions)
# B4h    lock count exceeded (INT 13 extensions)
# B5h    valid eject request failed (INT 13 extensions)
# B6h    volume present but read protected (INT 13 extensions)
# BBh    undefined error (hard disk)
# CCh    write fault (hard disk)
# E0h    status register error (hard disk)
# FFh    sense operation failed (hard disk)

disk_interrupts = FuncTable("INT 13h (disk)")
# Extended Read Sectors From Drive
@func(disk_interrupts, 0x42)
def extended_read_sectors(jitter, sys_):
    drive_idx = get_xl(jitter.cpu.DX)
    log.info("Extended read sectors, drive idx 0x%x" % drive_idx)

    dap = jitter.vm.get_mem((jitter.cpu.DS << 4) + jitter.cpu.SI, 16)
    dap_size, _, num_sect, buff_addr, abs_sect = struct.unpack("<BBHIQ", dap)

    if drive_idx >= 0x80:
        drive_idx -= 0x80

    try:
        hd = sys_.hd(drive_idx)
    except IndexError:
        log.info("  Drive idx %d empty, return error" % drive_idx)
        # AH=1 => error
        jitter.cpu.AX = set_16bit_reg(low=0, high=1)
        return

    log.info("  Read %d sectors at offset %d (to memory at 0x%04X)" % (num_sect, abs_sect, buff_addr))

    #print("  Read %d sectors from sector %d to %4x" % (num_sect, abs_sect, buff_addr))
    size = num_sect * SECTOR_LEN
    data = hd.read(abs_sect * SECTOR_LEN, size)

    # Emulate the fact that encryption has been done!
    if sys_.options.emulate_encrypted_hdd and abs_sect == 32:
        data = "\x01" + data[1:]

    log_hex(data)

    jitter.cpu.cf = 0 # No error
    # AL is the number of sectors read
    # AH is the return code, 0 = successful completion 
    jitter.cpu.AX = set_16bit_reg(low=int(len(data) / SECTOR_LEN), high=0)
    jitter.vm.set_mem((jitter.cpu.DS << 4) + buff_addr, data)

# Extended Write Sectors From Drive
@func(disk_interrupts, 0x43)
def extended_write_sectors(jitter, sys_):
    drive_idx = get_xl(jitter.cpu.DX)
    log.info("Extended write sectors, drive idx 0x%x" % drive_idx)

    # TODO: factorize code with above
    dap = jitter.vm.get_mem((jitter.cpu.DS << 4) + jitter.cpu.SI, 16)
    dap_size, _, num_sect, buff_addr, abs_sect = struct.unpack("<BBHIQ", dap)

    if drive_idx >= 0x80:
        drive_idx -= 0x80

    try:
        hd = sys_.hd(drive_idx)
    except IndexError:
        log.info("  Drive idx %d empty, return error" % drive_idx)
        # AH=1 => error
        jitter.cpu.AX = set_16bit_reg(low=0, high=1)
        return

    log.info("  Write %d sectors at offset %d (from memory at 0x%04X)" % (num_sect, abs_sect, buff_addr))

    len_ = num_sect*SECTOR_LEN
    data = jitter.vm.get_mem((jitter.cpu.DS << 4) + buff_addr, len_)
    log_hex(data)
    hd.write(abs_sect*SECTOR_LEN, data)

    jitter.cpu.cf = 0 # No error
    # AL is the number of sectors written
    jitter.cpu.AX = set_xl(jitter.cpu.AX, num_sect) 
    jitter.cpu.AX = set_xh(jitter.cpu.AX, 0) # AH is return code


# Get drive parameters
# http://www.ctyme.com/intr/rb-0621.htm
@func(disk_interrupts, 0x08)
def read_drive_parameters(jitter, sys_):
    drive_idx = jitter.cpu.DX & 0x00FF
    log.info("Read Drive Parameters, index 0x%x" % drive_idx)

    if drive_idx & 0x80 != 0x80:
        log.info(" drive idx 0x%x isn't a hard drive!" % drive_idx)
        jitter.cpu.cf = 1
        jitter.cpu.AX = set_xh(jitter.cpu.AX, 1) # AH return code 0 (OK)
        return

    drive_idx ^= 0x80

    if drive_idx >= sys_.hd_count:
        log.info("  Unknown drive idx %d!" % drive_idx)
        jitter.cpu.cf = 1
        jitter.cpu.AX = set_xh(jitter.cpu.AX, 1) # AH return code 0 (OK)
        return

    log.info("  Drive idx %d exists!" % drive_idx)
    hd = sys_.hd(drive_idx)
    
    # Max values
    CYLINDERS = 1023
    HEADS = 255
    SECTORS = 63

    jitter.cpu.cf = 0 # indicate that INT 13h are extensions supported
    jitter.cpu.DX = set_16bit_reg(sys_.hd_count, HEADS)
    jitter.cpu.CX = ((CYLINDERS & 0xFF) << 8) | ((CYLINDERS & 0x0300) >> 2) | SECTORS
    jitter.cpu.AX = set_xh(jitter.cpu.AX, 0) # AH return code 0 (OK)

###################
##### DISPLAY #####
###################
display_interrupts = FuncTable("INT 10h (display)")
@func(display_interrupts,0x0E)
def print_char(jitter, sys_):
    # Syscall 0xE : print character
    char = jitter.cpu.AX & 0x00FF
    page_num = jitter.cpu.BX & 0xFF00
    color = jitter.cpu.BX & 0x00FF

    if (char != 0x0D) and (char != 0x0A) and (char != 0x00):
        sys_.display_char(chr(char))
    else:
        sys_.display_char("\n")

@func(display_interrupts,0x0)
def set_video_mode(jitter, sys_):
    log.info( "Set video mode to: " + hex(jitter.cpu.AX & 0xFF00))

@func(display_interrupts,0x05)
def select_active_display_page(jitter, sys_):
    log.info( "Select active display page: " + hex(jitter.cpu.AX & 0xFF00))

@func(display_interrupts,0x01)
def set_text_mode_cursor_shape(jitter, sys_):
    log.info( "Set text-mode cursor shape")

@func(display_interrupts,0x06)
def scroll_up_win(jitter, sys_):
    log.info( "Scroll up window")

@func(display_interrupts,0x02)
def set_cursor_pos(jitter, sys_):
    log.info( "Set cursor position")

###################
##### KEYBOARD ####
###################

def character_to_scancode(c):
    # This is a hack to support some special keys. The right to do this (if
    # possible) would be to configure the terminal to give us the real original
    # scan code!
    special_chars = {
        27:  1,  # ESC
        10:  28, # Enter
        127: 14, # Backspace 
    }
    return special_chars.get(ord(c), 0xFF)

keyboard_interrupts = FuncTable("INT 16h (keyboard)")
@func(keyboard_interrupts,0x00)
#http://webpages.charter.net/danrollins/techhelp/0230.HTM
# Get next keystroke in a synchronous way. Clear the keyboard buffer.
def read_next_keystroke(jitter, sys_):
    c = async_kb.get_sync_char()
    jitter.cpu.AX = set_16bit_reg(ord(c), character_to_scancode(c))

@func(keyboard_interrupts,0x01)
#http://webpages.charter.net/danrollins/techhelp/0230.HTM
# Query keyboard status. If a character is in the keyboard buffer, return it
# but do not clear the buffer
def query_keyboard_status(jitter, sys_):
    c = async_kb.get_async_char()
    if not c is None:
        jitter.cpu.zf = 1
        jitter.cpu.AX = set_16bit_reg(ord(c), character_to_scancode(c))
    else:
        jitter.cpu.zf = 0

###################
##### DISK BOOT ###
###################
diskboot_interrupts = FuncTable("INT 19h (diskboot)")
@func(diskboot_interrupts, 0x02)
def reboot(jitter, sys_):
    # Here, we assume only one bootable disk (index 0)
    hd = sys_.hd(0)
    mbr = hd.read_sector(0)
    jitter.vm.set_mem(0x7C00, mbr)
    jitter.pc = 0x7C00

interrupt_handlers = {
    0x10: display_interrupts,
    0x13: disk_interrupts,
    0x16: keyboard_interrupts,
    0x19: diskboot_interrupts
}
