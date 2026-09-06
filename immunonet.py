#!/usr/bin/env python3
"""
ImmunoNet - visualizzatore di intrusion detection ispirato al sistema immunitario.

Idea: il traffico di rete viene trattato come cellule che circolano in un
corpo. Un motore di anomaly detection (statistico/euristico) marca i
pacchetti sospetti come "patogeni". Il sistema genera "anticorpi" che li
inseguono e li neutralizzano a schermo, in tempo reale, dentro il terminale.

Progetto didattico: la logica di detection e' reale (soglie configurabili,
rate limiting, deviazione statistica sulla dimensione dei pacchetti,
blacklist di porte), ma non sostituisce un IDS di produzione.

Uso:
    python3 immunonet.py                  # avvio con parametri di default
    python3 immunonet.py --rate 8         # piu' pacchetti al secondo
    python3 immunonet.py --anomaly 0.35   # piu' traffico anomalo
    python3 immunonet.py --fever 4        # soglia piu' bassa per la "febbre"

Tasti durante l'esecuzione:
    q  -> esci
    +  -> aumenta la soglia di rilevamento (meno sensibile)
    -  -> diminuisci la soglia di rilevamento (piu' sensibile)
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
    """Motore di rilevamento anomalie: rate limiting + z-score + porte sospette."""

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
    curses.init_pair(1, curses.COLOR_GREEN, -1)   # cellula normale
    curses.init_pair(2, curses.COLOR_RED, -1)     # patogeno
    curses.init_pair(3, curses.COLOR_CYAN, -1)    # anticorpo
    curses.init_pair(4, curses.COLOR_YELLOW, -1)  # header
    curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_RED)  # febbre

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

        # spawn nuovi pacchetti in base al rate richiesto
        spawn_accumulator += args.rate * tick
        while spawn_accumulator >= 1.0:
            pkt = generate_packet(args.anomaly)
            pkt.y = random.randint(lane_top, lane_bottom)
            detector.evaluate(pkt)
            packets.append(pkt)
            spawn_accumulator -= 1.0

        active_pathogens = sum(1 for p in packets if p.is_pathogen and not p.neutralized)
        fever = active_pathogens >= args.fever

        # assegna anticorpi ai patogeni senza cacciatore
        free_pathogens = [p for p in packets if p.is_pathogen and not p.neutralized and p.hunted_by is None]
        for ab in antibodies:
            if ab.target is None or ab.target.neutralized:
                ab.target = None
                if free_pathogens:
                    target = free_pathogens.pop(0)
                    target.hunted_by = ab
                    ab.target = target

        # muovi pacchetti
        for pkt in packets:
            speed = 0.5 + (pkt.size / 3000.0)
            pkt.x += speed if not pkt.is_pathogen else speed * 0.6
            pkt.ttl -= 1

        # muovi anticorpi verso il target, e verifica cattura
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

        # --- disegno ---
        stdscr.erase()
        header_attr = curses.color_pair(5) | curses.A_BOLD if fever else curses.color_pair(4) | curses.A_BOLD
        title = " IMMUNONET " + ("!! FEBBRE IN CORSO !!" if fever else "- sistema stabile")
        stdscr.addnstr(0, 0, title.center(width), width, header_attr)
        stats = (
            f" pacchetti: {detector.total_seen}  patogeni rilevati: {detector.total_pathogens}  "
            f"neutralizzati: {neutralized_count}  soglia z-score: {detector.size_z_threshold:.2f}"
        )
        stdscr.addnstr(1, 0, stats.ljust(width), width, curses.A_DIM)

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

        footer = " q: esci   +/-: sensibilita' detection   o = cellula  @ = patogeno  Y = anticorpo"
        if height > 2:
            stdscr.addnstr(height - 1, 0, footer.ljust(width), width, curses.A_DIM)

        stdscr.refresh()
        time.sleep(tick)
        tick_counter_unused = tick  # placeholder per chiarezza, nessun effetto


def main():
    parser = argparse.ArgumentParser(description="ImmunoNet - IDS didattico ispirato al sistema immunitario")
    parser.add_argument("--rate", type=float, default=4.0, help="pacchetti simulati al secondo (default: 4)")
    parser.add_argument("--anomaly", type=float, default=0.18, help="probabilita' di traffico anomalo, 0-1 (default: 0.18)")
    parser.add_argument("--fever", type=int, default=5, help="numero di patogeni attivi che scatena la 'febbre' (default: 5)")
    parser.add_argument("--antibodies", type=int, default=4, help="numero di anticorpi disponibili (default: 4)")
    parser.add_argument("--rate-threshold", type=float, default=40.0, help="soglia pacchetti/sec oltre cui il rate e' anomalo")
    args = parser.parse_args()

    open(LOG_FILE, "a").close()  # crea il file di log se non esiste
    curses.wrapper(run, args)


if __name__ == "__main__":
    main()
