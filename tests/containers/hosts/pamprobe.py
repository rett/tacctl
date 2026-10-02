#!/usr/bin/env python3
"""pamprobe.py <service> <user> <password> [phases]: run PAM phases, print each return code.
phases: comma list of auth,acct,open,close,chauthtok (default auth,acct)."""
import ctypes, ctypes.util, sys, time
from ctypes import POINTER, Structure, c_char_p, c_int, c_void_p, CFUNCTYPE, cast, byref
libpam = ctypes.CDLL(ctypes.util.find_library('pam') or 'libpam.so.0')
libc = ctypes.CDLL(None)
class Msg(Structure): _fields_ = [('style', c_int), ('msg', c_char_p)]
class Resp(Structure): _fields_ = [('resp', c_void_p), ('retcode', c_int)]
CONV = CFUNCTYPE(c_int, c_int, POINTER(POINTER(Msg)), POINTER(POINTER(Resp)), c_void_p)
class Conv(Structure): _fields_ = [('conv', CONV), ('appdata', c_void_p)]
libc.calloc.restype = c_void_p; libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
libc.strdup.restype = c_void_p; libc.strdup.argtypes = [c_char_p]
service, user, pw = sys.argv[1], sys.argv[2], sys.argv[3].encode()
phases = (sys.argv[4] if len(sys.argv) > 4 else 'auth,acct').split(',')
def conv(n, msgs, resps, _):
    arr = libc.calloc(n, ctypes.sizeof(Resp))
    r = cast(arr, POINTER(Resp))
    for i in range(n):
        m = msgs[i].contents
        if m.style in (1, 2):
            r[i].resp = libc.strdup(pw)
        elif m.msg:
            print('  [conv] %s' % m.msg.decode(errors='replace'))
    resps[0] = r
    return 0
c = Conv(CONV(conv), None)
h = c_void_p()
libpam.pam_strerror.restype = c_char_p
libpam.pam_strerror.argtypes = [c_void_p, c_int]
libpam.pam_start.argtypes = [c_char_p, c_char_p, POINTER(Conv), POINTER(c_void_p)]
rc = libpam.pam_start(service.encode(), user.encode(), byref(c), byref(h))
assert rc == 0, rc
libpam.pam_set_item.argtypes = [c_void_p, c_int, c_char_p]
libpam.pam_set_item(h, 3, b'pts/0'); libpam.pam_set_item(h, 4, b'127.0.0.1')
fn = {'auth': 'pam_authenticate', 'acct': 'pam_acct_mgmt', 'open': 'pam_open_session',
      'close': 'pam_close_session', 'chauthtok': 'pam_chauthtok'}
for p in phases:
    f = getattr(libpam, fn[p]); f.argtypes = [c_void_p, c_int]
    t = time.time(); rc = f(h, 0)
    print('%-9s rc=%d (%s) %.1fs' % (p, rc, libpam.pam_strerror(h, rc).decode(), time.time() - t))
libpam.pam_end.argtypes = [c_void_p, c_int]; libpam.pam_end(h, 0)
