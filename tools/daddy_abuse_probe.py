#!/usr/bin/env python3
"""Bounded malformed-handshake probe for a local/authorized test Daddy."""

import argparse
import concurrent.futures
import ipaddress
import socket
import time


def parse_target(value):
    if value.startswith("["):
        host, separator, port = value[1:].partition("]:")
    else:
        host, separator, port = value.rpartition(":")
    if not separator:
        raise argparse.ArgumentTypeError("target must be an IP address and port")
    try:
        address = ipaddress.ip_address(host)
        port_number = int(port)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    if address.is_reserved or address.is_unspecified or not (
        address.is_private or address.is_loopback or address.is_link_local
    ):
        raise argparse.ArgumentTypeError("target IP must be private, loopback, or link-local")
    if address.is_multicast or not 1 <= port_number <= 65535:
        raise argparse.ArgumentTypeError("target port or address is invalid")
    return str(address), port_number


def parse_source_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    if not address.is_loopback:
        raise argparse.ArgumentTypeError("source address must be loopback")
    return str(address)


def probe(target, deadline, source):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return "not-run"
    try:
        family = socket.AF_INET6 if ":" in target[0] else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(min(2.0, remaining))
            bind_address = (source, 0, 0, 0) if family == socket.AF_INET6 else (source, 0)
            connection.bind(bind_address)
            connection.connect(target)
            connection.sendall(b"NOPE\x00\x00\x00\x01x")
            try:
                response = connection.recv(64)
            except (TimeoutError, socket.timeout):
                return "timeout"
            return "closed" if not response else "response"
    except (ConnectionRefusedError, ConnectionResetError):
        return "rejected"
    except (TimeoutError, socket.timeout):
        return "timeout"
    except OSError:
        return "network-error"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, type=parse_target, help="private/loopback IP:port of your test Daddy")
    parser.add_argument("--test-mode", action="store_true", required=True, help="confirm this is an authorized test instance")
    parser.add_argument("--source-address", action="append", type=parse_source_address, help="loopback source IP; repeat to simulate multiple local sources")
    parser.add_argument("--requests", type=int, default=50, help="malformed handshakes, 1..10000 (default: 50)")
    parser.add_argument("--concurrency", type=int, default=4, help="simultaneous sockets, 1..16 (default: 4)")
    parser.add_argument("--duration", type=float, default=10, help="maximum runtime in seconds, 1..60 (default: 10)")
    args = parser.parse_args()
    if not 1 <= args.requests <= 10000:
        parser.error("--requests must be between 1 and 10000")
    if not 1 <= args.concurrency <= 16:
        parser.error("--concurrency must be between 1 and 16")
    if not 1 <= args.duration <= 60:
        parser.error("--duration must be between 1 and 60 seconds")
    sources = args.source_address or (["::1"] if ":" in args.target[0] else ["127.0.0.1"])
    target_version = ipaddress.ip_address(args.target[0]).version
    if any(ipaddress.ip_address(source).version != target_version for source in sources):
        parser.error("source address family must match the target")

    print("WARNING: authorized local resource-limit test only; malformed handshakes will be sent.")
    deadline = time.monotonic() + args.duration
    results = {"closed": 0, "rejected": 0, "response": 0, "timeout": 0, "network-error": 0, "not-run": 0}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [executor.submit(probe, args.target, deadline, sources[index % len(sources)]) for index in range(args.requests)]
        for future in concurrent.futures.as_completed(futures):
            results[future.result()] += 1
    print(
        f"target={args.target[0]}:{args.target[1]} results={results} "
        f"elapsed_limit={args.duration}s requests={args.requests} "
        f"concurrency={args.concurrency} sources={sources}"
    )


if __name__ == "__main__":
    main()
