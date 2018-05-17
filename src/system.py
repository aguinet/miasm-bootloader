#!/usr/bin/python2
import sys

class System:
    def __init__(self, hard_drives):
        self.__hd = hard_drives

    def get_drives(self):
        return self.__hd

    def hd(self, n):
        return self.__hd[n]

    @property
    def hd_count(self):
        return len(self.__hd)

    def display_char(self, c):
        sys.stdout.write(c)
        sys.stdout.flush()
