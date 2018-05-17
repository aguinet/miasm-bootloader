#!/usr/bin/env python2

import logging
from optparse import OptionParser
import sys
import functools

from miasm2.analysis.binary import Container
from miasm2.analysis.machine import Machine
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC, EXCEPT_INT_XX, EXCEPT_BREAKPOINT_MEMORY
from miasm2.jitter.jitload import ExceptionHandle
from miasm2.core.utils import upck16

from handlers import interrupt_handlers
from system import System
from disk import HardDrive, SECTOR_LEN
import async_kb

log = logging.getLogger("BIOS")
log.setLevel(logging.WARN)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(name)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

def exception_int(jitter, sys_):
    int_num = jitter.cpu.get_interrupt_num()
    func_num = (jitter.cpu.AX>>8) & 0xFF

    handler = interrupt_handlers.get(int_num, None)
    if handler is None:
        log.error("ERROR: Interruption %s handler not implemented " % hex(int_num))
        return False
    try:
        handler(func_num, jitter, sys_)
    except NotImplementedError as e:
        print(str(e))
        return False

    # Clear the interrupt exception flag
    jitter.cpu.set_exception(jitter.cpu.get_exception() & ~EXCEPT_INT_XX)
    return True

def handle_sti(jitter):
    jitter.pc += 1
    return True

_last_buf = None
def encrypt_start(jitter, options):
    global _last_buf
    # We put the breakpoint just after the "enter" instruction, so that we can
    # easily access stack-based arguments!

    if options.dump_keystream:
        buf_ptr  = upck16(jitter.vm.get_mem((jitter.cpu.SS << 4) + jitter.cpu.BP + 0xC, 2))
        buf_size = upck16(jitter.vm.get_mem((jitter.cpu.SS << 4) + jitter.cpu.BP + 0xE, 2))
        _last_buf = jitter.vm.get_mem(buf_ptr, buf_size)
    if options.skip_encr:
        jitter.pc = 0x9876
    return True

def encrypt_end(jitter, options):
    # Similar as above, we put the breakpoint just before the "leave" instruction!

    if options.dump_keystream:
        global _last_buf
        buf_ptr  = upck16(jitter.vm.get_mem((jitter.cpu.SS << 4) + jitter.cpu.BP + 0xC, 2))
        buf_size = upck16(jitter.vm.get_mem((jitter.cpu.SS << 4) + jitter.cpu.BP + 0xE, 2))
        encr_buf = jitter.vm.get_mem(buf_ptr, buf_size)
        keystream = ''.join(chr(ord(a)^ord(b)) for a,b in zip(_last_buf,encr_buf)).encode("hex")
        keystream = ' '.join(keystream[i:i+4] for i in xrange(0,len(keystream),4))
        print >>sys.stderr, "Keystream for next 2 sectors: %s" % keystream
    return True

def find_key_in_mem(jitter, key):
    # Find if the salsa20 key is still in memory!
    mem = jitter.vm.get_all_memory()
    print >>sys.stderr, "\n[+] Looking for key %s in memory..." % key.encode("hex")
    for addr,v in mem.iteritems():
        idx = v['data'].find(key)
        if idx == -1:
            continue
        print >>sys.stderr, "[+] Key found at address %s!" % hex(addr + idx)
        break
    else:
        print >>sys.stderr, "[-] Key not found in memory!"
    return True


def read_key_and_patch(jitter):
    # Key is still in the stack, at 0x674A. You can find this value by activating the
    # find_key_in_mem breakpoint!
    key = jitter.vm.get_mem(0x674A, 32)
    print >>sys.stderr, "\n[+] Key from memory: %s" % key.encode("hex")

    # Patch the bootloader in memory to decrypt using this key
    stub = open("stub","rb").read()
    jitter.vm.set_mem(0x82A8, stub)
    return True

def print_ip(jitter):
    print(hex(jitter.pc))
    return False

def emulate(hd_path, options):
    if options.verbose_bios:
        log.setLevel(logging.INFO)
    if options.verbose_bios_data:
        log.setLevel(logging.DEBUG)

    # Setup disk
    HD0 = HardDrive(hd_path, options.dry)
    sys_ = System([HD0])
    sys_.options = options

    # Set keyboard in asynchronous and raw mode!
    async_kb.init()

    # Load MBR
    mbr = HD0.read_sector(0)
    if (ord(mbr[SECTOR_LEN-2]), ord(mbr[SECTOR_LEN-1])) != (0x55, 0xaa): # last 2 bytes
        print >>sys.stderr, "ERROR: %s has not a correct MBR signature" % hd_path
        sys.exit(1)

    # Create VM
    stage1_addr = 0x7C00
    stage2_addr = 0x8000
    machine = Machine('x86_16')
    jitter = machine.jitter("llvm")
    jitter.vm.add_memory_page(stage1_addr, PAGE_READ | PAGE_WRITE | PAGE_EXEC, mbr, "NotPetyaS1")
    jitter.vm.add_memory_page(stage2_addr, PAGE_READ | PAGE_WRITE | PAGE_EXEC, "\x00"*SECTOR_LEN*32, "NotPetyaS2")
    jitter.vm.add_memory_page(0x0500, PAGE_READ | PAGE_WRITE, "\x00"*0x7700, "Stack")

    # Add exception handler
    jitter.add_exception_handler(EXCEPT_INT_XX, functools.partial(exception_int, sys_=sys_))

    #jitter.jit.log_regs = True
    #jitter.jit.log_mn = True
    if options.log_miasm_newblocks:
        jitter.jit.log_newbloc = True

    # STI instruction dirty hack
    jitter.add_breakpoint(0x7C0D, handle_sti)

    jitter.add_breakpoint(0x979C, functools.partial(encrypt_start, options=options))
    jitter.add_breakpoint(0x9876, functools.partial(encrypt_end, options=options))

    # Uncomment the following lines to find out when the key is written into the stack
    #jitter.exceptions_handler.callbacks[EXCEPT_BREAKPOINT_MEMORY] = []
    #jitter.add_exception_handler(EXCEPT_BREAKPOINT_MEMORY, print_ip)
    #jitter.vm.add_memory_breakpoint(0x674a, 1, PAGE_WRITE)

    # Get salsa20 key from sector 32
    key = HD0.read(32*SECTOR_LEN + 1, 32)

    if options.hook == "find_key":
        jitter.add_breakpoint(0x85AF, functools.partial(find_key_in_mem, key=key))
    elif options.hook == "patch_bootloader":
        jitter.add_breakpoint(0x85AF, read_key_and_patch)

    # Begin emulation
    jitter.init_run(stage1_addr)
    jitter.continue_run()

def main():
    parser = OptionParser("Usage: %prog [options] disk.raw")
    parser.add_option("--dry", action="store_true", dest="dry", default=False, help="Dry run: do not write modifications to disk")
    parser.add_option("--skip-encryption", action="store_true", dest="skip_encr", default=False, help="Do not execute the encryption code (leave the data in clear)")
    parser.add_option("--verbose-bios", action="store_true", dest="verbose_bios", default=False, help="Verbose message from the BIOS")
    parser.add_option("--verbose-bios-data", action="store_true", dest="verbose_bios_data", default=False, help="Verbose message from the BIOS, including data read/written throught the BIOS interrupts")
    parser.add_option("--log-miasm-newblocks", action="store_true", dest="log_miasm_newblocks", default=False, help="Miasm: log new encountered blocks")
    parser.add_option("--emulate-encrypted-hdd", action="store_true", dest="emulate_encrypted_hdd", default=False, help="Emulate the fact that the hard drive has already been encrypted")
    parser.add_option("--dump-keystream", action="store_true", dest="dump_keystream", default=False, help="Dump the keystream used for encryption")
    parser.add_option("--hook", type='choice', dest="hook", choices=['find_key', 'patch_bootloader', 'none'], default='none', help='Hook to set after encryption: find_key (find key in memory), patch_bootloader (patch the bootloader to use the key still in memory) or none (default)')
    options, args = parser.parse_args()
    if len(args) != 1:
        parser.error("missing disk path")

    emulate(args[0], options)

if __name__=="__main__":
    main()
