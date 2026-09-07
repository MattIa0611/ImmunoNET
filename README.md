# ImmunoNet

**An educational Intrusion Detection System (IDS) that treats network traffic like a living organism.**

Instead of reading logs and tables, you watch your traffic as a body fighting off an infection:

- every packet is a **cell** (`o`) circulating through the system
- an anomaly detection engine flags suspicious packets as **pathogens** (`@`)
- **antibodies** (`Y`) hunt them down and neutralize them (`x`) in real time
- if threats pile up too fast, the system enters **fever mode** (the header flashes and antibodies speed up)

It's not just visuals — the detection logic underneath is real, though deliberately simple, so it's easy to read and understand if you're just getting started.

## How detection works

Each simulated packet is checked against three criteria:

1. **Unusual destination port** — not among the common ports (80, 443, 22, 53, ...)
2. **Anomalous size** — computed via a z-score against the running mean/standard deviation of packet sizes seen so far
3. **Suspicious frequency** — too many packets within the same time window (rate limiting)

Each criterion met adds one point; a score of 2 or more marks the packet as a "pathogen". Every detected threat is also written to `threat_log.txt` with a timestamp, source IP, port, size, and score.

## Requirements

Just Python 3 and the standard library (`curses`, included by default on Linux/macOS). On Windows you need `windows-curses`:

```bash
pip install windows-curses
```

## Quick start

```bash
python3 immunonet.py
```

Available options:

```bash
python3 immunonet.py --rate 8 --anomaly 0.3 --fever 4
```

| Parameter | Meaning | Default |
|---|---|---|
| `--rate` | simulated packets per second | 4 |
| `--anomaly` | probability (0-1) that a generated packet is anomalous | 0.18 |
| `--fever` | active pathogens that trigger "fever" mode | 5 |
| `--antibodies` | number of available antibodies | 4 |
| `--rate-threshold` | packets/sec above which traffic is considered too fast | 40 |

## Runtime controls

- `q` — quit
- `+` — make detection less sensitive
- `-` — make detection more sensitive

## Legend

| Symbol | Meaning |
|---|---|
| `o` | normal packet |
| `@` | packet flagged as a pathogen |
| `Y` | antibody |
| `x` | pathogen just neutralized |

## Ideas to extend it

- Replace the simulated generator with real `.pcap` file parsing (e.g. via `scapy`)
- Add live sniffing of local traffic (requires elevated permissions)
- Export statistics to a web dashboard
- Add sonification: a distinct sound for each type of anomaly

## Disclaimer

This is an educational project meant to make the core concepts of anomaly detection visual and fun to explore. **It is not a production-grade IDS** and should not be relied on as the sole defense for real systems.

## License

MIT — see [LICENSE](LICENSE).
