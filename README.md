# ImmunoNet 🦠🛡️

**Un IDS (Intrusion Detection System) didattico che tratta il traffico di rete come un organismo vivente.**

Invece di leggere log e tabelle, guardi il tuo traffico come un corpo che si difende da un'infezione:

- ogni pacchetto è una **cellula** (`o`) che circola nel sistema
- un motore di anomaly detection marca i pacchetti sospetti come **patogeni** (`@`)
- gli **anticorpi** (`Y`) li inseguono e li neutralizzano (`x`) in tempo reale
- se le minacce si accumulano troppo in fretta, il sistema entra in **febbre** (l'header lampeggia e gli anticorpi accelerano)

Non è solo estetica: la logica di rilevamento sotto è reale, anche se volutamente semplice, pensata per essere letta e capita da chi è alle prime armi.

## Come funziona il rilevamento

Per ogni pacchetto simulato vengono controllate tre cose:

1. **Porta di destinazione insolita** — non è tra le porte comuni (80, 443, 22, 53, ...)
2. **Dimensione anomala** — calcolata con uno z-score sulla media/deviazione standard delle dimensioni viste finora
3. **Frequenza sospetta** — troppi pacchetti nella stessa finestra temporale (rate limiting)

Ogni criterio soddisfatto aggiunge un punto; da 2 punti in su, il pacchetto è un "patogeno". Ogni minaccia rilevata viene anche scritta in `threat_log.txt` con timestamp, IP sorgente, porta, dimensione e punteggio.

## Requisiti

Solo Python 3 e la libreria standard (`curses`, inclusa di default su Linux/macOS). Su Windows serve `windows-curses`:

```bash
pip install windows-curses
```

## Avvio rapido

```bash
python3 immunonet.py
```

Opzioni disponibili:

```bash
python3 immunonet.py --rate 8 --anomaly 0.3 --fever 4
```

| Parametro | Significato | Default |
|---|---|---|
| `--rate` | pacchetti simulati al secondo | 4 |
| `--anomaly` | probabilità (0-1) che un pacchetto sia generato come anomalo | 0.18 |
| `--fever` | patogeni attivi contemporaneamente che scatenano la "febbre" | 5 |
| `--antibodies` | numero di anticorpi disponibili | 4 |
| `--rate-threshold` | pacchetti/sec oltre cui il traffico è considerato troppo veloce | 40 |

## Comandi a runtime

- `q` — esci
- `+` — rendi il rilevamento meno sensibile
- `-` — rendi il rilevamento più sensibile

## Legenda

| Simbolo | Significato |
|---|---|
| `o` | pacchetto normale |
| `@` | pacchetto marcato come patogeno |
| `Y` | anticorpo |
| `x` | patogeno appena neutralizzato |

## Idee per estenderlo

- Sostituire il generatore simulato con la lettura di un file `.pcap` reale (es. tramite `scapy`)
- Aggiungere sniffing live del traffico locale (richiede permessi elevati)
- Esportare le statistiche in una dashboard web
- Aggiungere sonificazione: un suono diverso per ogni tipo di anomalia

## Disclaimer

Progetto educativo, pensato per capire i concetti base dell'anomaly detection in modo visivo e divertente. **Non è un IDS di produzione** e non va usato come unica difesa per sistemi reali.

## Licenza

MIT — vedi [LICENSE](LICENSE).
