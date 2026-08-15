# XTT - Extended Attributes Triage Tool

A forensic utility for the identification, extraction, and decoding of Extended Attributes (EAs) on macOS and Linux, purpose-built for DFIR workflows.

---

## What's New in v1.3.0

### T1564.014 static detection engine

- **`--detect`** (opt-in) — flags extended attributes consistent with the MITRE ATT&CK sub-technique *Hide Artifacts: Extended Attributes*. Matches are highlighted in **MAGENTA** and take precedence over entropy/skew highlights. Four rule classes in this release:
  - **PRIV-NS** — Linux `trusted.` / `security.` namespace attributes (require `CAP_SYS_ADMIN` to write; their presence is a triage-worthy anomaly)
  - **KNOWN-KEY** — attribute keys on a curated known-abuse list
  - **SUSP-KEY** — key names containing suspicious tokens (`payload`, `loader`, `shell`, `exec`, `beacon`, `c2`, etc.)
  - **EXEC-MAGIC** — attribute *values* beginning with executable magic bytes (ELF, PE/MZ, Mach-O, script shebang)
- **Detection column in CSV** — when `--detect` is active, a `detections` column is appended (CSV-injection guarded)
- Rules match on attribute **name/namespace** and a bounded magic-byte prefix only — no regex is evaluated against attacker-controlled attribute values (ReDoS/injection safe)

### Hostile-evidence hardening

v1.3.0 treats every path, filename, attribute name, and attribute value as adversary-controlled. The scanner was rewritten around that assumption:

- **No third-party dependencies** — the `xattr` package is gone. EAs are read through a bounded `ctypes` binding to `flistxattr`/`fgetxattr`, which lets XTT size every buffer before allocating it.
- **Descriptor-based traversal** — files are opened `O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK` and read through that one descriptor; `st_dev`/`st_ino` are compared before and after the open to close the TOCTOU window. Directory recursion uses `os.fwalk()` with `dir_fd`, so no path is ever re-resolved from a string.
- **Non-regular files are never opened** — opening device nodes on a live system has side effects (watchdogs arm, tape devices rewind). Symlinks and non-regular entries are recorded as *skipped*, not scanned.
- **Coverage is never overstated** — the summary reports files actually examined, and every deliberate skip and every failed operation is listed on stderr. A scan that hit any error or limit exits non-zero.
- **Bounded plist rendering** — `plistlib` deduplicates shared object references, so a small binary plist can parse cheaply and still expand to gigabytes under `repr()`. Parsed plists are rendered under an explicit node / depth / character budget and marked `[BPLIST TRUNCATED]` if they exceed it.
- **Full sanitization coverage** — file paths, attribute keys, content, and detection strings are all neutralized before display. Sanitization escapes non-printable characters including Unicode separators such as `U+2028`, which some CSV and JSON parsers treat as a line terminator.
- **Undecodable filenames survive export** — surrogate escapes from `os.fsdecode()` are neutralized before the CSV write, so a single unreadable filename cannot abort the report.
- **Oversized attributes still get rules applied** — values above the storage limit are read transiently for detection and entropy sampling rather than being silently handed an empty value; values above the read limit are declared as unexamined in the output.
- **Report integrity** — the CSV is created with `O_EXCL | O_NOFOLLOW` at mode `0600`, is refused if the path exists, and is removed if the write fails partway so a partial report can never be mistaken for a complete one.
- **Evidence-tree contamination guard** — the output path is resolved with `realpath()` and rejected if it lands inside the directory under examination, including by way of a symlinked parent.
- **Colour only when appropriate** — ANSI highlighting is emitted only when stdout is a TTY and `NO_COLOR` is unset, so piped or redirected output stays clean.

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
- **Full content visibility** — the CSV carries the whole decoded value up to a 20 MiB cap, with an explicit marker if that cap is hit; falls back to hex for non-UTF-8 binary EAs
- **macOS Binary Plist decoding** — handles `com.apple.metadata:kMDItemWhereFroms` and similar bplist EAs, under a bounded render budget
- **`com.apple.quarantine` structured parsing** — flags, timestamp (converted from macOS epoch), agent name, UUID
- **Shannon entropy analysis** (`-e`) — highlights EAs with entropy > 7.0 in **RED**
- **File mtime skew detection** (`-t`) — highlights recently modified files in **YELLOW**; configurable with `--skew-days`
- **T1564.014 detection** (`--detect`) — static rules for adversarial EA abuse; matches highlighted in **MAGENTA**
- **CSV export** (`-w`) with CSV injection prevention and refusal to overwrite
- **Symlink-safe** — symlinks are never followed or opened, at file and directory level, and every skip is reported

---

## Installation

```bash
git clone https://github.com/0xf4b10f/XTT.git
cd XTT
python3 xtt.py --version
```

**Requirements:** Python 3.6 or newer (the language floor; tested on 3.14). No third-party packages, no build step. macOS or Linux only — XTT binds the platform `flistxattr`/`fgetxattr` directly, and on any other platform every file fails with a recorded error and the run exits `2`.

> Earlier versions required `pip install xattr`. v1.3.0 removed that dependency.

---

## Usage

```
python3 xtt.py [-h] [--version] (-d DIRECTORY | -f FILE) [-e] [-t] [--skew-days N] [--detect] [-w OUTPUT.csv]
```

### Options

| Flag | Description |
|---|---|
| `-f FILE` | Scan a single file |
| `-d DIR` | Recursive directory scan |
| `-e` | Calculate Shannon entropy per EA |
| `-t` | Flag files with mtime within threshold (default: 3 days) |
| `--skew-days N` | Set skew threshold in days (positive finite float, default: 3.0) |
| `--detect` | Run T1564.014 static detection rules (highlights matches in MAGENTA) |
| `-w FILE.csv` | Export results to a new CSV (refuses to overwrite an existing path) |
| `--version` | Show version and exit |

### Output streams

The results table and the summary line go to **stdout**. Skipped entries and scan errors go to **stderr**, so a redirected report stays free of diagnostics:

```bash
python3 xtt.py -d /evidence/ > findings.txt 2> scan_errors.txt
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; every entry was either examined or explicitly reported as skipped |
| `1` | Output pipe closed early (`BrokenPipeError`) |
| `2` | Scan incomplete — an operation failed, a scan-level limit was reached, or the CSV report could not be written. Also returned for a rejected invocation (bad flag, symlink target, unusable `-w` path), which fails before any scanning happens |

A non-zero exit means the run's coverage is not what you asked for. Read stderr before treating a clean-looking table as a clean result.

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

### Detection — hunt for adversarial EA abuse (T1564.014)

```bash
python3 xtt.py --detect -d /path/to/dir/
```

### Full analysis with detection and report

```bash
python3 xtt.py -e -t --skew-days 2 --detect -d /path/to/dir/ -w /cases/report.csv
```

> The report path must not be inside the directory under examination, and must not already exist. Both are rejected before the scan begins.

---

## T1564.014 Detection Rules (`--detect`)

XTT includes an opt-in static detection engine aligned with MITRE ATT&CK sub-technique [T1564.014 — Hide Artifacts: Extended Attributes](https://attack.mitre.org/techniques/T1564/014/). Adversaries (including the Lazarus group) have been documented embedding payloads and loaders inside xattrs so that the primary file content — and therefore its hash — stays unchanged, evading integrity checks that don't inspect extended attributes.

The engine keys off attribute **name/namespace metadata** and a bounded **magic-byte prefix** of the value. It deliberately does **not** run regex against attacker-controlled attribute values, keeping it free of ReDoS and injection sinks.

| Rule | Trigger | Rationale |
|---|---|---|
| **PRIV-NS** | Linux `trusted.` / `security.` namespace attribute | These namespaces require `CAP_SYS_ADMIN` to write; unexpected presence is a privilege/namespace anomaly |
| **KNOWN-KEY** | Attribute key on curated known-abuse list | Keys observed in real-world tradecraft or strong anomalies outside expected system context |
| **SUSP-KEY** | Key name contains a suspicious token (`payload`, `loader`, `shell`, `exec`, `beacon`, `c2`, …) | Loader/stash naming patterns |
| **EXEC-MAGIC** | Value begins with executable magic (ELF, PE/MZ, Mach-O, `#!/` shebang) | Executable content hidden in an attribute value |

Matches are highlighted in **MAGENTA** and take precedence over entropy (RED) and skew (YELLOW) highlights. When `-w` is also set, a `detections` column is appended to the CSV.

> **Scope note:** This is a *triage* signal layer, not a verdict. Rules are intentionally conservative and name-based; a clean result does not prove absence of hidden data, and a match warrants analyst review rather than automated action. Rule tables live at the top of `xtt.py` and are meant to be extended per investigation.

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

## Resource Limits

Every allocation driven by evidence is capped. Limits are fixed constants at the top of `xtt.py`; raise them deliberately and only when the case requires it.

Two kinds of limit behave differently, and the distinction matters when you script around the exit code:

- **Scan-level limits** (`MAX_TOTAL_VALUE_BYTES`, `MAX_RESULTS`, `MAX_FILES`, `MAX_XATTR_LIST_SIZE`) stop or curtail collection. They mark the scan incomplete, print the reason to stderr, and force exit code `2`.
- **Value-level limits** (`MAX_EA_SIZE`, `MAX_EA_DETECT_SIZE`, `MAX_ENTROPY_SAMPLE_BYTES`, `MAX_PLIST_*`, `MAX_CONTENT_CHARS`, `MAX_RENDER_CONTENT_CHARS`) only bound how a single attribute is read, decoded, or displayed. They annotate the affected row in place — `[!] EA TOO LARGE …`, `[BPLIST TRUNCATED] …`, `[TRUNCATED: N characters omitted]` — and do **not** change the exit code, because nothing was missed at the file level.

`MAX_SCAN_ERRORS` is neither: it caps how many failures are listed individually, not what is scanned. Anything it suppresses is still counted in the total, and the errors that triggered it already force exit `2`.

| Constant | Default | Effect when exceeded |
|---|---|---|
| `MAX_EA_SIZE` | 10 MiB | Value is not stored or decoded; still read for detection and entropy |
| `MAX_EA_DETECT_SIZE` | 64 MiB | Value is not read at all; the output declares that content rules were not applied |
| `MAX_ENTROPY_SAMPLE_BYTES` | 4 MiB | Entropy for an oversized value is sampled over the first 4 MiB, and the output says so |
| `MAX_XATTR_LIST_SIZE` | 1 MiB | The file's attribute-name list is refused and recorded as an error |
| `MAX_PLIST_SIZE` | 1 MiB | Value is not parsed as a plist; falls back to UTF-8 or hex |
| `MAX_PLIST_RENDER_CHARS` / `MAX_PLIST_NODES` / `MAX_PLIST_DEPTH` | 256 KiB / 50,000 / 32 | Rendered as `[BPLIST TRUNCATED]` |
| `MAX_CONTENT_CHARS` | 20 MiB | Decoded content is truncated with an explicit marker |
| `MAX_RENDER_CONTENT_CHARS` | 4,096 | Terminal display only — the CSV still receives the full bounded value |
| `MAX_TOTAL_VALUE_BYTES` | 128 MiB | Scan stops; entries already collected are kept and reported |
| `MAX_RESULTS` | 100,000 | Scan stops; entries already collected are kept and reported |
| `MAX_FILES` | 1,000,000 | Traversal stops |
| `MAX_SCAN_ERRORS` | 10,000 | Further errors are counted but not listed individually |

---

## Known Limitations

- **Symlinks are never scanned.** On macOS a symlink can itself carry extended attributes; XTT reports each one as a skipped entry rather than following or opening it. Inspect those separately if the case calls for it.
- **`mtime` is not EA write time.** The kernel does not expose an EA modification timestamp through standard stat calls. Skew is a corroborating signal only.
- **Detection is name-based by design.** A clean `--detect` result does not prove absence of hidden data.
- **macOS and Linux only.** On any other platform the attribute backend refuses to initialize, so every file records an error and the run exits `2` — an empty table there means "unsupported platform", not "no extended attributes found".
- **A symlink passed directly to `-f` or `-d` is rejected** before the scan starts, not skipped silently. Point XTT at the resolved path if that is what you meant.

---

## References

- MITRE ATT&CK — T1564.014, Hide Artifacts: Extended Attributes — https://attack.mitre.org/techniques/T1564/014/
- MITRE ATT&CK — T1564, Hide Artifacts (parent technique) — https://attack.mitre.org/techniques/T1564/

---

## License

MIT — see [LICENSE.txt](LICENSE.txt)
