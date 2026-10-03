#!/usr/bin/env python3
"""Sample CPU, RSS, thread, and descriptor usage for a local test Daddy PID."""

import argparse
import os
import time


def read_sample(pid, clock_ticks):
    proc_dir = f"/proc/{pid}"
    with open(f"{proc_dir}/status", encoding="ascii") as status_file:
        status = status_file.read().splitlines()
    values = {}
    for line in status:
        if line.startswith(("VmRSS:", "VmHWM:", "Threads:")):
            key, value, *_ = line.split()
            values[key.rstrip(":")] = int(value)
    with open(f"{proc_dir}/stat", encoding="ascii") as stat_file:
        stat_text = stat_file.read()
    fields = stat_text[stat_text.rfind(")") + 2 :].split()
    cpu_ticks = int(fields[11]) + int(fields[12])
    values["cpu_seconds"] = cpu_ticks / clock_ticks
    values["fds"] = len(os.listdir(f"{proc_dir}/fd"))
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True, help="PID of the local authorized test Daddy")
    parser.add_argument("--test-mode", action="store_true", required=True, help="confirm this is a test process")
    parser.add_argument("--duration", type=float, default=60, help="sampling time in seconds, 1..3600")
    parser.add_argument("--interval", type=float, default=1, help="sampling interval in seconds, 0.1..10")
    args = parser.parse_args()
    if args.pid <= 1:
        parser.error("--pid must identify a non-init process")
    if not 1 <= args.duration <= 3600:
        parser.error("--duration must be between 1 and 3600 seconds")
    if not 0.1 <= args.interval <= 10:
        parser.error("--interval must be between 0.1 and 10 seconds")

    clock_ticks = os.sysconf("SC_CLK_TCK")
    started = time.monotonic()
    deadline = started + args.duration
    previous_time = None
    previous_cpu = None
    print("elapsed_s,rss_kib,peak_rss_kib,cpu_percent,threads,file_descriptors")
    while time.monotonic() < deadline:
        now = time.monotonic()
        try:
            sample = read_sample(args.pid, clock_ticks)
        except (FileNotFoundError, ProcessLookupError):
            break
        cpu_percent = 0.0
        if previous_time is not None:
            elapsed = now - previous_time
            cpu_percent = max(0.0, (sample["cpu_seconds"] - previous_cpu) / elapsed * 100)
        print(
            f"{now - started:.3f},{sample.get('VmRSS', 0)},{sample.get('VmHWM', 0)},"
            f"{cpu_percent:.2f},{sample.get('Threads', 0)},{sample['fds']}"
        )
        previous_time = now
        previous_cpu = sample["cpu_seconds"]
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(args.interval, remaining))


if __name__ == "__main__":
    main()
