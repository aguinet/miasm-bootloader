Bootloader emulation with Miasm (case of NotPetya)
==================================================

Dependencies
------------

* ``pip install -r requirements.txt``
* Miasm v0.1.1: ``git clone --depth=1 --branch=v0.1.1 https://github.com/cea-sec/miasm``

Run
---

The ``src/emulate_mbr.py`` script can emulate the bootloader, and has some
options to carry some experiments::

  $ python /path/to/emulate_mbr --help

  Usage: emulate_mbr.py [options] disk.raw

  Options:
    -h, --help            show this help message and exit
    --dry                 Dry run: do not write modifications to disk
    --skip-encryption     Do not execute the encryption code (leave the data in
                          clear)
    --verbose-bios        Verbose message from the BIOS
    --verbose-bios-data   Verbose message from the BIOS, including data
                          read/written throught the BIOS interrupts
    --log-miasm-newblocks
                          Miasm: log new encountered blocks
    --emulate-encrypted-hdd
                          Emulate the fact that the hard drive has already been
                          encrypted
    --dump-keystream      Dump the keystream used for encryption
    --hook=HOOK           Hook to set after encryption: find_key (find key in
                          memory), patch_bootloader (patch the bootloader to use
                          the key still in memory) or none (default)


The ``disk.raw.bz2`` file is a disk example with a NotPetya bootloader and a
simple NTFS partition. Beware that the size of the decompressed file is ~1GB.

Authors
-------

* lafouine <lafouine@nopsys.org>
* Adrien Guinet <adrien@guinet.me>
