# XTT - Extended Attributes Triage Tool

A forensic utility for the identification, extraction, and decoding of Extended Attributes (EAs) on macOS and Linux, purpose-built for DFIR workflows.

---

## What's New in v1.2.2

- **`com.apple.quarantine` parser** — structured decoding of quarantine flags, macOS-epoch timestamp, agent bundle ID, and UUID directly from the EA
- **Configurable skew threshold** — `--skew-days N` replaces the hardcoded 72-hour window; set it to match your investigation timeline
- **Hardened terminal sanitization** — all control characters (not just `\x1b`) are neutralized to prevent terminal injection from adversary-controlled EA content
- **Entropy computed on raw bytes** — entropy now runs before content decoding for accuracy; the old order could distort scores on bplist-decoded values
- **Architecture refactor** — scan, render, summarize, and export are fully separated functions; easier to extend and test
- **`--version` flag** added
- **Skew disclaimer in summary** — the output now explicitly notes that `mtime` reflects file data changes, not EA write time

---

## Features

- **Single file or recursive directory scan** via `-f` / `-d`
- **Full content visibility** — no truncation; falls back to hex for non-UTF-8 binary EAs
- **macOS Binary Plist decoding** — handles `com.apple.metadata:kMDItemWhereFroms` and similar bplist EAs
- **`com.apple.quarantine` structured parsing** — flags, timestamp (converted from macOS epoch), agent name, UUID
- **Shannon entropy analysis** (`-e`) — highlights EAs with entropy > 7.0 in **RED**
- **File mtime skew detection** (`-t`) — highlights recently modified files in **YELLOW**; configurable with `--skew-days`
- **CSV export** (`-w`) with CSV injection prevention
- **Symlink-safe** — symlinks are skipped at both file and directory level

---

## Installation

```bash
git clone https://github.com/0xf4b10f/XTT.git
cd XTT
pip install -r requirements.txt
```

---

## Usage

```
python3 xtt.py [-h] [--version] (-d DIRECTORY | -f FILE) [-e] [-t] [--skew-days N] [-w OUTPUT.csv]
```

### Options

| Flag | Description |
|---|---|
| `-f FILE` | Scan a single file |
| `-d DIR` | Recursive directory scan |
| `-e` | Calculate Shannon entropy per EA |
| `-t` | Flag files with mtime within threshold (default: 3 days) |
| `--skew-days N` | Set skew threshold in days (float, default: 3.0) |
| `-w FILE.csv` | Export results to CSV |
| `--version` | Show version and exit |

---

## Examples

### Scan a directory recursively

```bash
python3 xtt.py -d /path/to/dir/
```

### Analyze a single file

```bash
python3 xtt.py -f suspicious.dmg
```

### Entropy analysis — detect encrypted or packed payloads

```bash
python3 xtt.py -e -d /path/to/dir/
```

### Time skew analysis — flag files modified in the last 24 hours

```bash
python3 xtt.py -t --skew-days 1 -d /path/to/dir/
```

> **Note:** `mtime` reflects changes to file data, not to extended attributes. EA write time is not exposed by the kernel through standard stat calls. Treat skew alerts as a corroborating signal, not a definitive indicator.

### Full analysis with report

```bash
python3 xtt.py -e -t --skew-days 2 -d /path/to/dir/ -w report.csv
```

---

## Entropy Reference

| Score | Interpretation | Forensic Action |
|---|---|---|
| 0.0 – 3.0 | Highly structured / empty | Likely padding or null bytes |
| 3.0 – 6.0 | Standard text / code | Likely legitimate configuration |
| 6.0 – 7.5 | Packed / obfuscated | Suspicious — possible packed payload or Base64 blob |
| 7.5 – 8.0 | Encrypted / compressed | **Critical** — high probability of hidden payload or encrypted C2 config |

---

## macOS Quarantine EA

When `com.apple.quarantine` is present, XTT decodes it into structured components instead of displaying raw bytes:

```
[QUARANTINE] flags=USER_APPROVED (0083) | ts=2024-11-14 18:32:01 | agent=com.apple.Safari | uuid=<uuid>
```

Known quarantine flags decoded: `USER_APPROVED`, `SANDBOXED`, `DOWNLOAD_INCOMPLETE`.

---

## License

MIT — see [LICENSE.txt](LICENSE.txt)
