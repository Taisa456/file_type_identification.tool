# FileScope — File Type Identification Tool

A command-line tool that reads magic bytes (file signatures) to identify the real type of a file, regardless of its extension. Detects extension spoofing commonly used to disguise malware — such as a Windows executable renamed to `.pdf` or a PHP webshell disguised as `.jpg`.

## Why this matters

Operating systems rely on file extensions to decide how to open files, but extensions can be trivially changed. An attacker can rename `payload.exe` to `invoice.pdf`, and a user who double-clicks it may execute malware. Antivirus tools answer "is this file malicious?" — this tool answers "is this file lying about what it is?"

## Features

- **40+ file signatures** — executables (PE, ELF, Mach-O), documents (PDF, Office), images (PNG, JPEG, GIF), archives (ZIP, RAR, 7z, GZIP), scripts (PHP, shell), audio/video, databases, and more
- **Extension mismatch detection** — flags files where the extension doesn't match the magic bytes
- **Risk scoring** — dangerous combinations (exe-as-pdf, PHP-as-jpg, elf-as-mp3) are flagged as critical
- **Passive extension protection** — `.txt`, `.csv`, `.log`, `.md` and similar data-only formats are flagged if they contain executable content
- **Shannon entropy analysis** — calculates byte-level randomness (0–8 scale) to detect packed, encrypted, or obfuscated payloads that pass signature checks
- **SHA-256 hashing** — generates file hashes for cross-referencing with VirusTotal or other threat intel platforms
- **Batch scanning** — scan entire directories with optional recursion
- **JSON export** — machine-readable reports for integration with SIEM or other tools
- **Colored CLI output** — severity-coded results (green/yellow/red) for fast triage

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/filescope.git
cd filescope
```

Python 3.6+ required. No external dependencies.

## Usage

```bash
# Scan a single suspicious file
python3 file_identifier.py suspicious_file.pdf

# Scan a directory
python3 file_identifier.py -d /path/to/downloads/

# Recursive scan with verbose output (shows magic bytes and descriptions)
python3 file_identifier.py -d /quarantine/ -r -v

# Show only mismatches — filter out clean files for faster triage
python3 file_identifier.py -d /uploads/ --mismatches-only

# Export results to JSON
python3 file_identifier.py -d /uploads/ --json report.json

# Combine flags
python3 file_identifier.py -d /quarantine/ -r -v --mismatches-only --json report.json
```

## Sample output

**PHP webshell disguised as PDF:**
```
  financial_report.pdf  [!! MALWARE RISK !!]
  ──────────────────────────────────────────────────
  Extension:     .pdf
  Real type:     PHP Script
  Expected ext:  .php
  Size:          33 B
  Entropy:       4.05/8.0 (moderate — normal text)
  SHA-256:       07a9b0ee3d58709e9bf36285539992afd1fd697f8ed53fc1aae65499f22877dd

  ⚠  Extension '.pdf' suggests PDF, but magic bytes indicate PHP Script
     This file may be malware disguised with a fake extension.
     DO NOT OPEN. Quarantine and investigate.
```

**ELF binary disguised as PDF:**
```
  quarterly_report.pdf  [!! MALWARE RISK !!]
  ──────────────────────────────────────────────────
  Extension:     .pdf
  Real type:     ELF
  Expected ext:  .elf/.so/.bin
  Size:          154.9 KB
  Entropy:       5.97/8.0 (above average — mixed content)
  SHA-256:       833d6f9cf3ede2225d80eaa159ef78a141c92842a691179aec37d182cc808a5c

  ⚠  Extension '.pdf' suggests PDF, but magic bytes indicate ELF
     This file may be malware disguised with a fake extension.
     DO NOT OPEN. Quarantine and investigate.
```

## How it works

1. **Magic byte analysis** — reads the first bytes of a file and compares against a database of known file signatures (e.g., `4D 5A` = Windows PE, `7F 45 4C 46` = ELF, `3C 3F 70 68 70` = PHP)
2. **Extension comparison** — checks if the file's extension matches what the magic bytes indicate
3. **Risk scoring** — classifies mismatches as warnings (wrong but benign, like `.doc` with ZIP magic) or critical (executable content behind a passive extension)
4. **Entropy analysis** — measures Shannon entropy to flag files with abnormally high randomness, which can indicate encryption or packing even when magic bytes look normal
5. **Hash generation** — computes SHA-256 for threat intel lookups on platforms like VirusTotal

## Entropy guide

| Range | Label | Meaning |
|-------|-------|---------|
| 0–1.0 | Very low | Nearly empty or repetitive |
| 1.0–3.5 | Low | Structured data |
| 3.5–5.0 | Moderate | Normal text |
| 5.0–7.0 | Above average | Mixed or binary content |
| 7.0–7.5 | High | Compressed or native binary |
| 7.5–7.9 | Very high | Compressed/encrypted |
| 7.9–8.0 | **Suspicious** | **Likely packed or encrypted payload** |

## Use cases

- **SOC triage** — quickly scan a quarantine folder to identify spoofed files
- **Upload validation** — verify files match their claimed type before processing
- **Incident response** — identify malware payloads hidden behind benign extensions
- **CTF / security training** — learn how magic bytes and file signatures work


