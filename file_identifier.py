#!/usr/bin/env python3
"""
File Type Identification Tool
Reads magic bytes (file signatures) to identify the real file type,
detecting extension spoofing used to hide malware.
"""

import os
import sys
import json
import math
import hashlib
import argparse
from pathlib import Path
from datetime import datetime

# Magic byte signatures: (hex_bytes, offset, file_type, extension, description)
SIGNATURES = [
    # Executables
    (b"\x4d\x5a", 0, "PE Executable", ".exe/.dll/.sys", "Windows executable"),
    (b"\x7f\x45\x4c\x46", 0, "ELF", ".elf/.so/.bin", "Linux executable"),
    (b"\xfe\xed\xfa\xce", 0, "Mach-O 32-bit", ".macho", "macOS executable"),
    (b"\xfe\xed\xfa\xcf", 0, "Mach-O 64-bit", ".macho", "macOS 64-bit executable"),
    (b"\xca\xfe\xba\xbe", 0, "Mach-O Universal", ".macho", "macOS universal binary"),
    (b"\xce\xfa\xed\xfe", 0, "Mach-O 32-bit (reversed)", ".macho", "macOS executable (reversed)"),
    (b"\xcf\xfa\xed\xfe", 0, "Mach-O 64-bit (reversed)", ".macho", "macOS 64-bit executable (reversed)"),

    # Scripts (check before generic text)
    (b"#!/", 0, "Shell Script", ".sh/.py/.pl", "Script with shebang"),
    (b"<?php", 0, "PHP Script", ".php", "PHP script"),
    (b"<?\n", 0, "PHP Script (short tag)", ".php", "PHP script (short open tag)"),

    # Documents
    (b"\x25\x50\x44\x46", 0, "PDF", ".pdf", "PDF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "MS Office (OLE2)", ".doc/.xls/.ppt", "Legacy MS Office document"),
    (b"\x50\x4b\x03\x04", 0, "ZIP/Office XML", ".zip/.docx/.xlsx/.pptx/.jar/.apk", "ZIP archive or modern Office doc"),

    # Images
    (b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", 0, "PNG", ".png", "PNG image"),
    (b"\xff\xd8\xff", 0, "JPEG", ".jpg/.jpeg", "JPEG image"),
    (b"\x47\x49\x46\x38\x37\x61", 0, "GIF87a", ".gif", "GIF image (87a)"),
    (b"\x47\x49\x46\x38\x39\x61", 0, "GIF89a", ".gif", "GIF image (89a)"),
    (b"\x42\x4d", 0, "BMP", ".bmp", "Bitmap image"),
    (b"\x49\x49\x2a\x00", 0, "TIFF (LE)", ".tiff/.tif", "TIFF image (little-endian)"),
    (b"\x4d\x4d\x00\x2a", 0, "TIFF (BE)", ".tiff/.tif", "TIFF image (big-endian)"),
    (b"\x52\x49\x46\x46", 0, "RIFF", ".webp/.avi/.wav", "RIFF container (WebP/AVI/WAV)"),
    (b"\x00\x00\x01\x00", 0, "ICO", ".ico", "Windows icon"),
    (b"\x00\x00\x02\x00", 0, "CUR", ".cur", "Windows cursor"),

    # Archives
    (b"\x52\x61\x72\x21\x1a\x07", 0, "RAR", ".rar", "RAR archive"),
    (b"\x37\x7a\xbc\xaf\x27\x1c", 0, "7-Zip", ".7z", "7-Zip archive"),
    (b"\x1f\x8b", 0, "GZIP", ".gz/.tar.gz", "GZIP compressed"),
    (b"\x42\x5a\x68", 0, "BZIP2", ".bz2", "BZIP2 compressed"),
    (b"\xfd\x37\x7a\x58\x5a\x00", 0, "XZ", ".xz", "XZ compressed"),
    (b"\x75\x73\x74\x61\x72", 257, "TAR", ".tar", "TAR archive"),

    # Audio/Video
    (b"\x49\x44\x33", 0, "MP3 (ID3)", ".mp3", "MP3 audio with ID3 tag"),
    (b"\xff\xfb", 0, "MP3", ".mp3", "MP3 audio"),
    (b"\xff\xf3", 0, "MP3", ".mp3", "MP3 audio"),
    (b"\x66\x4c\x61\x43", 0, "FLAC", ".flac", "FLAC audio"),
    (b"\x4f\x67\x67\x53", 0, "OGG", ".ogg", "OGG container"),
    (b"\x1a\x45\xdf\xa3", 0, "MKV/WebM", ".mkv/.webm", "Matroska container"),
    (b"\x00\x00\x00", 0, "MP4/MOV", ".mp4/.mov/.m4a", "MPEG-4 container (check ftyp at offset 4)"),

    # Database
    (b"\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74", 0, "SQLite", ".db/.sqlite", "SQLite database"),

    # Crypto / Certs
    (b"\x30\x82", 0, "DER Certificate", ".der/.cer", "DER encoded certificate"),

    # Misc
    (b"\x7b", 0, "JSON (likely)", ".json", "Possibly JSON"),
    (b"\x3c\x3f\x78\x6d\x6c", 0, "XML", ".xml/.svg/.html", "XML document"),
    (b"\x3c\x21\x44\x4f\x43", 0, "HTML", ".html/.htm", "HTML document"),
]

# Extension-to-type mapping for mismatch detection
EXTENSION_MAP = {
    ".exe": ["PE Executable"],
    ".dll": ["PE Executable"],
    ".sys": ["PE Executable"],
    ".pdf": ["PDF"],
    ".png": ["PNG"],
    ".jpg": ["JPEG"],
    ".jpeg": ["JPEG"],
    ".gif": ["GIF87a", "GIF89a"],
    ".bmp": ["BMP"],
    ".doc": ["MS Office (OLE2)"],
    ".xls": ["MS Office (OLE2)"],
    ".ppt": ["MS Office (OLE2)"],
    ".docx": ["ZIP/Office XML"],
    ".xlsx": ["ZIP/Office XML"],
    ".pptx": ["ZIP/Office XML"],
    ".zip": ["ZIP/Office XML"],
    ".rar": ["RAR"],
    ".7z": ["7-Zip"],
    ".gz": ["GZIP"],
    ".tar": ["TAR"],
    ".mp3": ["MP3 (ID3)", "MP3"],
    ".mp4": ["MP4/MOV"],
    ".mov": ["MP4/MOV"],
    ".mkv": ["MKV/WebM"],
    ".webm": ["MKV/WebM"],
    ".flac": ["FLAC"],
    ".ogg": ["OGG"],
    ".ico": ["ICO"],
    ".tiff": ["TIFF (LE)", "TIFF (BE)"],
    ".tif": ["TIFF (LE)", "TIFF (BE)"],
    ".webp": ["RIFF"],
    ".avi": ["RIFF"],
    ".wav": ["RIFF"],
    ".db": ["SQLite"],
    ".sqlite": ["SQLite"],
    ".json": ["JSON (likely)"],
    ".xml": ["XML"],
    ".svg": ["XML"],
    ".html": ["HTML", "XML"],
    ".htm": ["HTML", "XML"],
    ".sh": ["Shell Script"],
    ".py": ["Shell Script"],  # if it has a shebang
    ".jar": ["ZIP/Office XML"],
    ".apk": ["ZIP/Office XML"],
    ".php": ["PHP Script", "PHP Script (short tag)"],
}

# Dangerous combinations: real type + fake extension = high risk
DANGEROUS_COMBOS = {
    "PE Executable": [".pdf", ".jpg", ".jpeg", ".png", ".gif", ".doc", ".docx",
                      ".xls", ".xlsx", ".txt", ".mp3", ".mp4"],
    "ELF": [".pdf", ".jpg", ".jpeg", ".png", ".gif", ".txt", ".doc"],
    "Shell Script": [".pdf", ".jpg", ".jpeg", ".png", ".txt", ".doc"],
    "Mach-O 32-bit": [".pdf", ".jpg", ".png", ".txt", ".doc"],
    "Mach-O 64-bit": [".pdf", ".jpg", ".png", ".txt", ".doc"],
    "PHP Script": [".pdf", ".jpg", ".jpeg", ".png", ".txt", ".doc", ".docx", ".mp3"],
    "PHP Script (short tag)": [".pdf", ".jpg", ".jpeg", ".png", ".txt", ".doc", ".docx", ".mp3"],
}


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        for attr in ["RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "GRAY", "BOLD", "RESET"]:
            setattr(cls, attr, "")


def calculate_entropy(filepath):
    """Calculate Shannon entropy of a file. Scale: 0 (uniform) to 8 (max random).
    Normal text: 3.5-5.0 | Compressed/images: 7.0-7.8 | Encrypted/packed: 7.9+"""
    with open(filepath, "rb") as f:
        data = f.read()
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return round(entropy, 2)


def get_entropy_label(entropy):
    """Human-readable entropy assessment."""
    if entropy < 1.0:
        return "very low", "nearly empty or repetitive"
    elif entropy < 3.5:
        return "low", "structured data"
    elif entropy < 5.0:
        return "moderate", "normal text"
    elif entropy < 7.0:
        return "above average", "mixed content"
    elif entropy < 7.5:
        return "high", "compressed or binary"
    elif entropy < 7.9:
        return "very high", "compressed/encrypted"
    else:
        return "suspicious", "likely packed or encrypted payload"


def calculate_sha256(filepath):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def identify_file(filepath):
    """Read magic bytes and identify the real file type."""
    filepath = Path(filepath)
    if not filepath.exists():
        return {"error": f"File not found: {filepath}"}
    if not filepath.is_file():
        return {"error": f"Not a file: {filepath}"}

    file_size = filepath.stat().st_size
    if file_size == 0:
        return {
            "path": str(filepath),
            "name": filepath.name,
            "extension": filepath.suffix.lower(),
            "size": 0,
            "detected_type": "Empty file",
            "expected_extensions": "N/A",
            "description": "File has zero bytes",
            "magic_hex": "",
            "entropy": 0.0,
            "entropy_label": "empty",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "mismatch": False,
            "mismatch_detail": "",
            "risk": "none",
        }

    # Read first 512 bytes (enough for all signatures including TAR at offset 257)
    with open(filepath, "rb") as f:
        header = f.read(512)

    magic_hex = " ".join(f"{b:02x}" for b in header[:16])
    extension = filepath.suffix.lower()

    # Try to match against known signatures
    detected = None
    for sig_bytes, offset, file_type, expected_ext, description in SIGNATURES:
        if len(header) > offset and header[offset:offset + len(sig_bytes)] == sig_bytes:
            detected = {
                "type": file_type,
                "expected_ext": expected_ext,
                "description": description,
            }
            break

    if not detected:
        detected = {
            "type": "Unknown",
            "expected_ext": "?",
            "description": "No matching signature found",
        }

    # Check for extension mismatch
    mismatch = False
    risk = "none"
    mismatch_detail = ""

    # Extensions that should never contain executable/script content
    PASSIVE_EXTENSIONS = {".txt", ".csv", ".log", ".md", ".cfg", ".ini", ".conf"}

    if extension and detected["type"] != "Unknown":
        expected_types = EXTENSION_MAP.get(extension, [])
        if expected_types and detected["type"] not in expected_types:
            mismatch = True
            mismatch_detail = f"Extension '{extension}' suggests {'/'.join(expected_types)}, but magic bytes indicate {detected['type']}"

            # Check if it's a dangerous combo
            dangerous_exts = DANGEROUS_COMBOS.get(detected["type"], [])
            if extension in dangerous_exts:
                risk = "critical"
            elif mismatch:
                risk = "warning"

        # Passive extensions: no expected type, but should never be executable
        elif not expected_types and extension in PASSIVE_EXTENSIONS:
            executable_types = {"PE Executable", "ELF", "Mach-O 32-bit", "Mach-O 64-bit",
                                "Mach-O Universal", "Shell Script", "PHP Script",
                                "PHP Script (short tag)"}
            if detected["type"] in executable_types:
                mismatch = True
                risk = "critical"
                mismatch_detail = f"Extension '{extension}' is a passive data format, but magic bytes indicate {detected['type']}"

    # Calculate entropy and hash
    entropy = calculate_entropy(filepath)
    entropy_label, entropy_note = get_entropy_label(entropy)
    sha256 = calculate_sha256(filepath)

    # Entropy-based risk escalation: if file looks normal by magic bytes
    # but has suspiciously high entropy, flag it
    if not mismatch and entropy >= 7.9 and detected["type"] not in ("GZIP", "BZIP2", "XZ", "7-Zip", "RAR", "PNG", "JPEG", "MKV/WebM"):
        risk = "warning"
        mismatch = True
        mismatch_detail = f"Entropy {entropy}/8.0 is abnormally high for {detected['type']} — possible packed/encrypted payload"

    return {
        "path": str(filepath),
        "name": filepath.name,
        "extension": extension,
        "size": file_size,
        "detected_type": detected["type"],
        "expected_extensions": detected["expected_ext"],
        "description": detected["description"],
        "magic_hex": magic_hex,
        "entropy": entropy,
        "entropy_label": f"{entropy_label} — {entropy_note}",
        "sha256": sha256,
        "mismatch": mismatch,
        "mismatch_detail": mismatch_detail,
        "risk": risk,
    }


def print_result(result, verbose=False):
    """Print a single file analysis result."""
    if "error" in result:
        print(f"  {Colors.RED}ERROR{Colors.RESET} {result['error']}")
        return

    # Status indicator
    if result["risk"] == "critical":
        status = f"{Colors.RED}{Colors.BOLD}!! MALWARE RISK !!{Colors.RESET}"
    elif result["risk"] == "warning":
        status = f"{Colors.YELLOW}MISMATCH{Colors.RESET}"
    else:
        status = f"{Colors.GREEN}OK{Colors.RESET}"

    print(f"\n  {Colors.BOLD}{result['name']}{Colors.RESET}  [{status}]")
    print(f"  {Colors.GRAY}{'─' * 50}{Colors.RESET}")

    # File details
    size_str = format_size(result["size"])
    print(f"  Extension:     {result['extension'] or '(none)'}")
    print(f"  Real type:     {Colors.CYAN}{result['detected_type']}{Colors.RESET}")
    print(f"  Expected ext:  {result['expected_extensions']}")
    print(f"  Size:          {size_str}")

    # Entropy with color coding
    entropy = result.get("entropy", 0)
    entropy_label = result.get("entropy_label", "")
    if entropy >= 7.9:
        entropy_color = Colors.RED
    elif entropy >= 7.0:
        entropy_color = Colors.YELLOW
    else:
        entropy_color = Colors.GREEN
    print(f"  Entropy:       {entropy_color}{entropy}/8.0{Colors.RESET} ({entropy_label})")

    # SHA-256
    sha256 = result.get("sha256", "")
    print(f"  SHA-256:       {Colors.GRAY}{sha256}{Colors.RESET}")

    if verbose:
        print(f"  Magic bytes:   {Colors.GRAY}{result['magic_hex']}{Colors.RESET}")
        print(f"  Description:   {result['description']}")

    if result["mismatch"]:
        color = Colors.RED if result["risk"] == "critical" else Colors.YELLOW
        print(f"\n  {color}⚠  {result['mismatch_detail']}{Colors.RESET}")
        if result["risk"] == "critical":
            print(f"  {Colors.RED}   This file may be malware disguised with a fake extension.{Colors.RESET}")
            print(f"  {Colors.RED}   DO NOT OPEN. Quarantine and investigate.{Colors.RESET}")


def format_size(size):
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def scan_directory(directory, recursive=False):
    """Scan all files in a directory."""
    directory = Path(directory)
    if not directory.is_dir():
        print(f"{Colors.RED}Error: {directory} is not a directory{Colors.RESET}")
        return []

    results = []
    pattern = "**/*" if recursive else "*"
    for filepath in sorted(directory.glob(pattern)):
        if filepath.is_file():
            results.append(identify_file(filepath))
    return results


def print_summary(results):
    """Print scan summary."""
    total = len(results)
    errors = sum(1 for r in results if "error" in r)
    ok = sum(1 for r in results if r.get("risk") == "none")
    warnings = sum(1 for r in results if r.get("risk") == "warning")
    critical = sum(1 for r in results if r.get("risk") == "critical")

    print(f"\n  {Colors.BOLD}Scan summary{Colors.RESET}")
    print(f"  {Colors.GRAY}{'─' * 50}{Colors.RESET}")
    print(f"  Total files:   {total}")
    print(f"  {Colors.GREEN}Clean:       {ok}{Colors.RESET}")
    if warnings:
        print(f"  {Colors.YELLOW}Mismatches:  {warnings}{Colors.RESET}")
    if critical:
        print(f"  {Colors.RED}Critical:    {critical}{Colors.RESET}")
    if errors:
        print(f"  {Colors.RED}Errors:      {errors}{Colors.RESET}")
    print()


def export_json(results, output_path):
    """Export results to JSON."""
    report = {
        "scan_time": datetime.now().isoformat(),
        "total_files": len(results),
        "critical": sum(1 for r in results if r.get("risk") == "critical"),
        "warnings": sum(1 for r in results if r.get("risk") == "warning"),
        "results": results,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Identify real file types by reading magic bytes. Detects extension spoofing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s suspicious_file.pdf
  %(prog)s -d /path/to/downloads/ -r
  %(prog)s -d /quarantine/ -v --json report.json
  %(prog)s file1.exe file2.jpg file3.pdf
        """,
    )
    parser.add_argument("files", nargs="*", help="Files to analyze")
    parser.add_argument("-d", "--directory", help="Scan all files in a directory")
    parser.add_argument("-r", "--recursive", action="store_true", help="Scan subdirectories recursively")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show magic bytes and descriptions")
    parser.add_argument("--json", metavar="FILE", help="Export results to JSON file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--mismatches-only", action="store_true", help="Only show files with mismatches")

    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    if not args.files and not args.directory:
        parser.print_help()
        sys.exit(1)

    print(f"\n  {Colors.BOLD}File Type Identifier{Colors.RESET} {Colors.GRAY}— magic byte analysis{Colors.RESET}")
    print(f"  {Colors.GRAY}{'═' * 50}{Colors.RESET}")

    results = []

    # Scan individual files
    if args.files:
        for filepath in args.files:
            results.append(identify_file(filepath))

    # Scan directory
    if args.directory:
        results.extend(scan_directory(args.directory, args.recursive))

    if not results:
        print(f"\n  {Colors.YELLOW}No files found.{Colors.RESET}\n")
        sys.exit(0)

    # Print results
    for result in results:
        if args.mismatches_only and not result.get("mismatch"):
            continue
        print_result(result, verbose=args.verbose)

    print_summary(results)

    # Export JSON if requested
    if args.json:
        export_json(results, args.json)


if __name__ == "__main__":
    main()
