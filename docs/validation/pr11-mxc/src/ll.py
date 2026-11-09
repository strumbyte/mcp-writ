import ctypes

libc = ctypes.CDLL(None, use_errno=True)
# landlock_create_ruleset(attr=NULL, size=0, flags=LANDLOCK_CREATE_RULESET_VERSION=1)
r = libc.syscall(444, None, 0, 1)
print("landlock_abi =", r, "errno =", ctypes.get_errno())
