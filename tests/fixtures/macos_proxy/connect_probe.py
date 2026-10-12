#!/usr/bin/env python3
"""CONNECT probe for `macos-proxy-run` e2e tests.

Usage: connect_probe.py [--noauth] [--early] <host:port>

Reads the injected `https_proxy` env (loopback URL with the per-launch
credential in userinfo), CONNECTs to the target through it, prints the
proxy's response status, and — after a `200` — proves the splice by
sending `PING` and printing the first echoed line (`PING-BACK:<line>`).
Bytes received past the request head (e.g. an echo of pipelined
`EARLY` payload) are kept and count toward that echo read.

Exit code is 0 whenever the protocol round-trip completed (a 4xx/5xx
from the proxy is still a completed exchange — the *test* asserts the
status), 2 on a transport-level failure.
"""

import base64
import os
import socket
import sys
import urllib.parse

argv = [a for a in sys.argv[1:] if a != ""]
noauth = "--noauth" in argv
early = "--early" in argv
target = next(a for a in argv if not a.startswith("--"))

url = urllib.parse.urlparse(os.environ["https_proxy"])
s = socket.create_connection((url.hostname, url.port), timeout=5)
req = f"CONNECT {target} HTTP/1.1\r\n"
if not noauth:
    cred = base64.b64encode(
        f"{url.username}:{urllib.parse.unquote(url.password or '')}".encode()
    ).decode()
    req += f"Proxy-Authorization: Basic {cred}\r\n"
req += "\r\n"
try:
    s.sendall(req.encode() + (b"EARLY\n" if early else b""))
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(4096)
        if not chunk:
            print("EOF")
            sys.exit(2)
        head += chunk
    status = head.split(b" ", 2)[1].decode()
    print(status)
    if status == "200":
        # Bytes already received past the head's \r\n\r\n are tunneled
        # payload — keep them for the echo read.
        tail = head.split(b"\r\n\r\n", 1)[1]
        s.sendall(b"PING\n")
        buf = tail
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        line = buf.split(b"\n", 1)[0].decode(errors="replace").strip()
        print(f"PING-BACK:{line}")
    sys.exit(0)
except OSError as e:
    print(f"ERR:{e}")
    sys.exit(2)
