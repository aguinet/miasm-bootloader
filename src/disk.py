import logging
log = logging.getLogger("BIOS")

SECTOR_LEN = 512

class HardDriveAbstract:
    def read_sector(self, sec):
        return self.read(sec*SECTOR_LEN, SECTOR_LEN)

class HardDrive(HardDriveAbstract):
    def __init__(self, file_, dry_mode = False):
        self.fd = open(file_, "r+")
        self.dry_mode = dry_mode

    def read(self, offset, n):
        log.debug("[disk] read %d bytes at offset %d" % (n, offset))
        self.fd.seek(offset)
        buf = self.fd.read(n)
        if len(buf) != n:
            raise Exception("unable to read %d bytes, got %d" % (n, len(buf)))
        return buf

    def write(self, offset, buf):
        log.debug("[disk] write %d bytes at offset %d" % (len(buf), offset))
        if self.dry_mode:
            return len(buf)
        self.fd.seek(offset)
        length = self.fd.write(buf)
        self.fd.flush()
        return length
