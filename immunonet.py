#!/usr/bin/env python3
"""
ImmunoNet - an intrusion detection visualizer inspired by the immune system.

Idea: network traffic is treated like cells circulating through a body. An
anomaly detection engine (statistical/heuristic) flags suspicious packets as
"pathogens". The system spawns "antibodies" that hunt them down and
neutralize them live, right inside your terminal.

Educational project: the detection logic underneath is real (configurable
thresholds, rate limiting, statistical deviation on packet size, a port
blacklist), but this is not a production-grade IDS.

Usage:
    python3 immunonet.py                  # start with default parameters
    python3 immunonet.py --rate 8         # more packets per second
    python3 immunonet.py --anomaly 0.35   # more anomalous traffic
    python3 immunonet.py --fever 4        # lower threshold to trigger "fever"

Keys while running:
    q  -> quit
    +  -> raise the detection threshold (less sensitive)
    -  -> lower the detection threshold (more sensitive)
"""

import argparse
import curses
import math
import random
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

COMMON_PORTS = {80, 443, 22, 53, 25, 110, 143, 993, 995, 21, 3306, 5432}
SUSPICIOUS_PORTS = [4444, 6667, 31337, 12345, 9001, 1337]
LOG_FILE = "threat_log.txt"


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


@dataclass
class Packet:
    src_ip: str
    dst_port: int
    size: int
    timestamp: float
    is_pathogen: bool = False
    score: float = 0.0
    x: float = 0.0
    y: int = 0
    ttl: int = 60
    hunted_by: object = None
    neutralized: bool = False


@dataclass
class Antibody:
    x: float
    y: int
    target: Packet = None
    speed: float = 2.2


def generate_packet(anomaly_chance: float) -> Packet:
    forced_anomaly = random.random() < anomaly_chance
    if forced_anomaly:
        port = random.choice(SUSPICIOUS_PORTS + [random.randint(49152, 65535)])
        size = random.randint(3000, 9000)
    else:
        port = random.choice(list(COMMON_PORTS))
        size = random.randint(40, 1400)
    return Packet(src_ip=random_ip(), dst_port=port, size=size, timestamp=time.time())


class AnomalyDetector:
    """Detection engine: rate limiting + z-score on size + suspicious ports."""

    def __init__(self, rate_window=5.0, rate_threshold=40, size_z_threshold=2.5):
        self.rate_window = rate_window
        self.rate_threshold = rate_threshold
        self.size_z_threshold = size_z_threshold
        self._timestamps = deque()
        self._sizes = deque(maxlen=200)
        self.total_seen = 0
        self.total_pathogens = 0

    def adjust_threshold(self, delta: float):
        self.size_z_threshold = max(0.5, self.size_z_threshold + delta)

    def evaluate(self, pkt: Packet) -> Packet:
        now = pkt.timestamp
        self._timestamps.append(now)
        while self._timestamps and now - self._timestamps[0] > self.rate_window:
            self._timestamps.popleft()
        rate = len(self._timestamps) / self.rate_window

        self._sizes.append(pkt.size)
        mean = sum(self._sizes) / len(self._sizes)
        variance = sum((s - mean) ** 2 for s in self._sizes) / len(self._sizes)
        std = math.sqrt(variance) if variance > 0 else 1.0
        z = (pkt.size - mean) / std

        score = 0.0
        if pkt.dst_port not in COMMON_PORTS:
            score += 1.0
        if z > self.size_z_threshold:
            score += 1.0
        if rate > self.rate_threshold:
            score += 1.0

        pkt.score = score
        pkt.is_pathogen = score >= 2.0

        self.total_seen += 1
        if pkt.is_pathogen:
            self.total_pathogens += 1
            self._log_threat(pkt, rate, z)

        return pkt

    @staticmethod
    def _log_threat(pkt: Packet, rate: float, z: float):
        with open(LOG_FILE, "a") as f:
            f.write(
                f"{datetime.now().isoformat(timespec='seconds')} "
                f"src={pkt.src_ip} port={pkt.dst_port} size={pkt.size} "
                f"score={pkt.score:.1f} rate={rate:.1f}/s z={z:.2f}\n"
            )


def run(stdscr, args):
    curses.curs_set(0)
    stdscr.nodelay(True)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)   # normal cell
    curses.init_pair(2, curses.COLOR_RED, -1)     # pathogen
    curses.init_pair(3, curses.COLOR_CYAN, -1)    # antibody
    curses.init_pair(4, curses.COLOR_YELLOW, -1)  # header
    curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_RED)  # fever mode

    detector = AnomalyDetector(rate_threshold=args.rate_threshold)
    packets = []
    antibodies = [Antibody(x=0, y=y) for y in range(2, 2 + args.antibodies)]
    neutralized_count = 0
    spawn_accumulator = 0.0
    tick = 0.05  # ~20 fps
    fever = False

    while True:
        try:
            ch = stdscr.getkey()
        except curses.error:
            ch = None
        if ch == "q":
            break
        elif ch == "+":
            detector.adjust_threshold(0.25)
        elif ch == "-":
            detector.adjust_threshold(-0.25)

        height, width = stdscr.getmaxyx()
        lane_top, lane_bottom = 3, max(4, height - 3)

        # spawn new packets at the requested rate
        spawn_accumulator += args.rate * tick
        while spawn_accumulator >= 1.0:
            pkt = generate_packet(args.anomaly)
            pkt.y = random.randint(lane_top, lane_bottom)
            detector.evaluate(pkt)
            packets.append(pkt)
            spawn_accumulator -= 1.0

        active_pathogens = sum(1 for p in packets if p.is_pathogen and not p.neutralized)
        fever = active_pathogens >= args.fever

        # assign antibodies to pathogens that have no hunter yet
        free_pathogens = [p for p in packets if p.is_pathogen and not p.neutralized and p.hunted_by is None]
        for ab in antibodies:
            if ab.target is None or ab.target.neutralized:
                ab.target = None
                if free_pathogens:
                    target = free_pathogens.pop(0)
                    target.hunted_by = ab
                    ab.target = target

        # move packets
        for pkt in packets:
            speed = 0.5 + (pkt.size / 3000.0)
            pkt.x += speed if not pkt.is_pathogen else speed * 0.6
            pkt.ttl -= 1

        # move antibodies toward their target, check for a catch
        for ab in antibodies:
            if ab.target:
                if ab.x < ab.target.x:
                    ab.x += ab.speed * (2.0 if fever else 1.0)
                ab.y = ab.target.y
                if abs(ab.x - ab.target.x) < 1.5:
                    ab.target.neutralized = True
                    ab.target.ttl = min(ab.target.ttl, 12)
                    neutralized_count += 1
                    ab.target = None

        packets = [p for p in packets if p.ttl > 0 and p.x < width]

        # --- draw ---
        stdscr.erase()
        header_attr = curses.color_pair(5) | curses.A_BOLD if fever else curses.color_pair(4) | curses.A_BOLD
        title = " IMMUNONET " + ("!! FEVER IN PROGRESS !!" if fever else "- system stable")
        stats = (
            f" packets: {detector.total_seen}  pathogens detected: {detector.total_pathogens}  "
            f"neutralized: {neutralized_count}  z-score threshold: {detector.size_z_threshold:.2f}"
        )
        try:
            stdscr.addnstr(0, 0, title.center(width)[:width], width, header_attr)
            if height > 1:
                stdscr.addnstr(1, 0, stats.ljust(width)[:width], width, curses.A_DIM)
        except curses.error:
            pass

        for pkt in packets:
            if pkt.x < 0 or pkt.x >= width or pkt.y >= height:
                continue
            if pkt.neutralized:
                symbol = "x"
                attr = curses.color_pair(3)
            elif pkt.is_pathogen:
                symbol = "@"
                attr = curses.color_pair(2) | curses.A_BOLD
            else:
                symbol = "o"
                attr = curses.color_pair(1)
            try:
                stdscr.addch(pkt.y, int(pkt.x), symbol, attr)
            except curses.error:
                pass

        for ab in antibodies:
            if 0 <= ab.y < height and 0 <= int(ab.x) < width:
                try:
                    stdscr.addch(ab.y, int(ab.x), "Y", curses.color_pair(3) | curses.A_BOLD)
                except curses.error:
                    pass

        footer = " q: quit   +/-: detection sensitivity   o = cell  @ = pathogen  Y = antibody"
        if height > 2 and width > 1:
            try:
                stdscr.addnstr(height - 1, 0, footer.ljust(width - 1), width - 1, curses.A_DIM)
            except curses.error:
                pass

        stdscr.refresh()
        time.sleep(tick)


def main():
    parser = argparse.ArgumentParser(description="ImmunoNet - an educational IDS inspired by the immune system")
    parser.add_argument("--rate", type=float, default=4.0, help="simulated packets per second (default: 4)")
    parser.add_argument("--anomaly", type=float, default=0.18, help="probability of anomalous traffic, 0-1 (default: 0.18)")
    parser.add_argument("--fever", type=int, default=5, help="active pathogens that trigger 'fever' mode (default: 5)")
    parser.add_argument("--antibodies", type=int, default=4, help="number of antibodies available (default: 4)")
    parser.add_argument("--rate-threshold", type=float, default=40.0, help="packets/sec above which the rate is considered anomalous")
    args = parser.parse_args()

    open(LOG_FILE, "a").close()  # create the log file if it doesn't exist
    curses.wrapper(run, args)


if __name__ == "__main__":
    main()
