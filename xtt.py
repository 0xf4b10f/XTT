import os
import xattr
import plistlib
import argparse
import sys
import csv
import math
import unicodedata
import time
from collections import Counter

# ANSI escape codes
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"

MAX_EA_SIZE = 10 * 1024 * 1024
VERSION = "1.2.2"

# macOS quarantine flag bits
QUARANTINE_FLAGS = {
    0x0001: "USER_APPROVED",
    0x0002: "SANDBOXED",
    0x0100: "DOWNLOAD_INCOMPLETE",
}


def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    data_len = len(data)
    counts = Counter(data)
    for count in counts.values():
        p = count / data_len
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def sanitize_for_terminal(text):
    """
    Neutralizes all control characters to prevent terminal injection.
    EA content is adversary-controlled; treat everything non-printable.
    """
    if not isinstance(text, str):
        text = str(text)
    return "".join(
        c if unicodedata.category(c)[0] != "C" else f"[{ord(c):#04x}]"
        for c in text
    )


def sanitize_for_csv(text):
    """Prevents CSV injection while preserving data."""
    text_str = str(text)
    if text_str and text_str[0] in ("=", "+", "-", "@"):
        return f"'{text_str}"
    return text_str


def parse_quarantine(raw_value):
    """
    Parses com.apple.quarantine EA into structured components.
    Format: <flags>;<timestamp_hex>;<agent_name>;<uuid>
    """
    try:
        decoded = raw_value.decode("utf-8").strip()
        parts = decoded.split(";")
        if len(parts) < 2:
            return decoded

        flags_raw = int(parts[0], 16)
        flag_names = [name for bit, name in QUARANTINE_FLAGS.items() if flags_raw & bit]
        flag_str = "|".join(flag_names) if flag_names else "NONE"

        ts_str = ""
        if parts[1]:
            try:
                # macOS quarantine timestamp: seconds since 2001-01-01
                MAC_EPOCH_OFFSET = 978307200
                ts = int(parts[1], 16) + MAC_EPOCH_OFFSET
                ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))
            except Exception:
                ts_str = parts[1]

        agent = parts[2] if len(parts) > 2 else ""
        uuid = parts[3] if len(parts) > 3 else ""

        return f"[QUARANTINE] flags={flag_str} ({parts[0]}) | ts={ts_str} | agent={agent} | uuid={uuid}"
    except Exception:
        return f"[QUARANTINE RAW] {raw_value.hex()}"


def decode_ea_content(attr_name, raw_value):
    """
    Decodes EA content with full visibility.
    Handles quarantine, bplist, UTF-8, and binary fallback.
    """
    if attr_name == "com.apple.quarantine":
        return parse_quarantine(raw_value)

    if raw_value.startswith(b"bplist00"):
        try:
            parsed = plistlib.loads(raw_value)
            return f"[BPLIST] {parsed}"
        except Exception:
            pass  # fall through to other decoders

    try:
        return raw_value.decode("utf-8").strip()
    except UnicodeDecodeError:
        return f"HEX:{raw_value.hex()}"


def process_file(path, calc_entropy=False, skew_threshold_days=None):
    """
    Processes a single file and returns a list of EA result dicts.
    Returns empty list on symlinks, permission errors, or no EAs.
    NOTE: mtime reflects file data changes, not EA changes. Skew is
    file-level only and does not imply EA was recently written.
    """
    if os.path.islink(path):
        return []

    results = []
    readable_mtime = "N/A"
    is_skewed = False

    try:
        if skew_threshold_days is not None:
            file_stat = os.stat(path)
            mtime = file_stat.st_mtime
            readable_mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))
            if (time.time() - mtime) < (skew_threshold_days * 86400):
                is_skewed = True

        attrs = xattr.listxattr(path)
        if not attrs:
            return []

        for attr_name in attrs:
            raw_val = xattr.getxattr(path, attr_name)

            if len(raw_val) > MAX_EA_SIZE:
                content_raw = f"[!] EA TOO LARGE ({len(raw_val)} bytes)"
                entropy_score = "N/A"
            else:
                # Entropy on raw bytes before decoding (more accurate)
                entropy_score = calculate_entropy(raw_val) if calc_entropy else "N/A"
                content_raw = decode_ea_content(attr_name, raw_val)

            entry = {
                "file_path": path,
                "attribute_key": attr_name,
                "content": content_raw,
                "entropy": entropy_score,
                "is_high_entropy": isinstance(entropy_score, float) and entropy_score > 7,
                "is_skewed": is_skewed,
                "mtime": readable_mtime,
            }
            results.append(entry)

    except (PermissionError, OSError):
        pass

    return results


def collect_results(target, is_dir, calc_entropy=False, skew_threshold_days=None):
    """Walks target and collects all EA results. Separated from rendering."""
    all_results = []

    if is_dir:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for file in files:
                path = os.path.join(root, file)
                all_results.extend(process_file(path, calc_entropy, skew_threshold_days))
    else:
        all_results.extend(process_file(target, calc_entropy, skew_threshold_days))

    return all_results


def render_results(results, calc_entropy=False, check_skew=False):
    """Prints results to stdout with ANSI highlights."""
    col_path = 40
    col_mtime = 20
    col_key = 30
    col_entropy = 7

    line_length = col_path + 3 + col_key + 3 + 10  # base
    if calc_entropy:
        line_length += col_entropy + 3
    if check_skew:
        line_length += col_mtime + 3

    header = f"\n{'File Path':<{col_path}} | "
    if check_skew:
        header += f"{'Last Modified (file)':<{col_mtime}} | "
    header += f"{'Key':<{col_key}}"
    if calc_entropy:
        header += f" | {'Entropy':<{col_entropy}}"
    header += " | Content"

    print(header)
    print("-" * line_length)

    for entry in results:
        display_content = sanitize_for_terminal(entry["content"])
        line = f"{entry['file_path']:<{col_path}} | "
        if check_skew:
            line += f"{entry['mtime']:<{col_mtime}} | "
        line += f"{entry['attribute_key']:<{col_key}}"
        if calc_entropy:
            line += f" | {entry['entropy']:<{col_entropy}}"
        line += f" | {display_content}"

        if entry.get("is_high_entropy"):
            print(f"{RED}{line}{RESET}")
        elif entry.get("is_skewed"):
            print(f"{YELLOW}{line}{RESET}")
        else:
            print(line)

    print("-" * line_length)


def summarize_results(results, files_scanned, calc_entropy=False, check_skew=False):
    """Prints summary statistics."""
    files_with_ea = len({e["file_path"] for e in results})
    high_entropy = sum(1 for e in results if e.get("is_high_entropy"))
    skew_alerts = len({e["file_path"] for e in results if e.get("is_skewed")})

    summary = f"Summary: Scanned: {files_scanned} | w/ EA: {files_with_ea}"
    if calc_entropy:
        summary += f" | High Entropy (>7): {high_entropy}"
    if check_skew:
        summary += f" | Files w/ Recent mtime: {skew_alerts} [NOTE: mtime ≠ EA write time]"
    print(summary)
    print("-" * 80)


def export_results(results, output_file, calc_entropy=False, check_skew=False):
    """Writes results to CSV. Separated from scan and render logic."""
    if not results:
        print("[!] No results to export.")
        return

    # Declarative column ordering — no fragile index arithmetic
    fieldnames = ["file_path"]
    if check_skew:
        fieldnames.append("mtime")
    fieldnames += ["attribute_key", "content"]
    if calc_entropy:
        fieldnames.append("entropy")

    with open(output_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in results:
            sanitized = dict(row)
            sanitized["content"] = sanitize_for_csv(row["content"])
            writer.writerow(sanitized)

    print(f"[+] Report exported to: {output_file}")


def count_files(target, is_dir):
    """Counts files to scan for summary stats."""
    if not is_dir:
        return 1
    count = 0
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        count += len(files)
    return count


def main():
    parser = argparse.ArgumentParser(
        description="XTT: Extended Attribute Triage Tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"XTT {VERSION}")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--directory", help="Recursive scan of a directory.")
    group.add_argument("-f", "--file", help="Scan a single file.")

    parser.add_argument("-e", "--entropy", action="store_true", help="Calculate Shannon entropy per EA.")
    parser.add_argument(
        "-t", "--time-skew",
        action="store_true",
        help="Flag files whose mtime is within --skew-days (default: 3). "
             "NOTE: reflects file data mtime, not EA write time.",
    )
    parser.add_argument(
        "--skew-days",
        type=float,
        default=3.0,
        metavar="N",
        help="Threshold in days for --time-skew (default: 3).",
    )
    parser.add_argument("-w", "--write", help="Export results to CSV.")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    target = args.directory if args.directory else args.file
    is_dir = bool(args.directory)
    skew_days = args.skew_days if args.time_skew else None

    if not os.path.exists(target):
        print(f"Error: Path '{target}' not found.")
        sys.exit(1)

    files_scanned = count_files(target, is_dir)
    results = collect_results(target, is_dir, args.entropy, skew_days)
    render_results(results, args.entropy, args.time_skew)
    summarize_results(results, files_scanned, args.entropy, args.time_skew)

    if args.write:
        export_results(results, args.write, args.entropy, args.time_skew)


if __name__ == "__main__":
    main()
