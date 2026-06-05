#!/usr/bin/env python3
"""UDP ping — sends to UDP echo port (7) by default."""

import socket
import time
import sys

ECHO_PORT = 7
TIMEOUT = 2.0
PAYLOAD = b"uping"


def resolve_port(arg):
    if arg.lower() == "echo":
        return ECHO_PORT
    try:
        return int(arg)
    except ValueError:
        raise SystemExit(f"unknown port: {arg}")


def uping(host, port):
    try:
        addr_info = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except socket.gaierror as e:
        raise SystemExit(f"cannot resolve {host}: {e}")

    family, _, _, _, addr = addr_info[0]

    seq = 0
    print(f"UPING {host} ({addr[0]}) port {port}/udp")

    try:
        while True:
            seq += 1
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.settimeout(TIMEOUT)
                t0 = time.perf_counter()
                s.sendto(PAYLOAD, addr)
                try:
                    data, _ = s.recvfrom(256)
                    ms = (time.perf_counter() - t0) * 1000
                    print(f"{len(data)} bytes from {addr[0]}: seq={seq} time={ms:.2f} ms")
                except socket.timeout:
                    print(f"Request timeout for seq {seq}")
            time.sleep(1)
    except KeyboardInterrupt:
        print()


def main():
    if len(sys.argv) < 2:
        raise SystemExit(f"usage: {sys.argv[0]} host [port|echo]")

    host = sys.argv[1]
    port = resolve_port(sys.argv[2]) if len(sys.argv) > 2 else ECHO_PORT
    uping(host, port)


if __name__ == "__main__":
    main()
