import select
import sys
import termios
import tty
import copy
import atexit

_kb_buf = None
_init = False

def init():
    global _init
    if _init:
        return
    old_flags = termios.tcgetattr(sys.stdin)
    atexit.register(termios.tcsetattr, sys.stdin, termios.TCSADRAIN, old_flags)
    new_flags = copy.deepcopy(old_flags)
    new_flags[3] &= ~termios.ICANON & ~termios.ECHO
    termios.tcsetattr(sys.stdin, termios.TCSAFLUSH, new_flags)
    _init = True

def get_async_char():
    global _kb_buf
    if _kb_buf:
        return _kb_buf
    if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
        _kb_buf = sys.stdin.read(1)
        return _kb_buf
    return None

def get_sync_char():
    global _kb_buf
    if _kb_buf:
        ret, _kb_buf = _kb_buf, None
        return ret
    return sys.stdin.read(1)
