"""XTT v1.3.0 -- Extended Attribute Triage Tool.

XTT inventories extended attributes on macOS and Linux for DFIR triage. All
filesystem metadata and attribute data are treated as hostile evidence, and the
implementation is written to hold four properties:

"""

import argparse
import csv
import ctypes
import errno
import math
import os
import plistlib
import stat
import sys
import time
from collections import Counter


VERSION = "1.3.0"

RED = "\033[31m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RESET = "\033[0m"

# Resource limits are deliberately fixed so hostile evidence cannot request
# unbounded allocations. Values above MAX_EA_SIZE are reported but not stored.
MAX_EA_SIZE = 10 * 1024 * 1024
MAX_EA_DETECT_SIZE = 64 * 1024 * 1024
MAX_XATTR_LIST_SIZE = 1024 * 1024
MAX_PLIST_SIZE = 1024 * 1024
MAX_CONTENT_CHARS = 20 * 1024 * 1024
MAX_TOTAL_VALUE_BYTES = 128 * 1024 * 1024
MAX_RESULTS = 100_000
MAX_FILES = 1_000_000
MAX_SCAN_ERRORS = 10_000
MAX_QUARANTINE_HEX_CHARS = 32
MAX_ENTROPY_SAMPLE_BYTES = 4 * 1024 * 1024
XATTR_RETRIES = 3

# plistlib deduplicates shared object references, so parsing is cheap while
# rendering is not. These budgets bound the rendered form, not the input size.
MAX_PLIST_RENDER_CHARS = 256 * 1024
MAX_PLIST_NODES = 50_000
MAX_PLIST_DEPTH = 32
MAX_PLIST_LEAF_CHARS = 256
MAX_PLIST_LEAF_BYTES = 128

# A single attribute value may legitimately be megabytes long. Terminal output
# is truncated for display only; --write still receives the bounded full value.
MAX_RENDER_CONTENT_CHARS = 4096

QUARANTINE_FLAGS = {
    0x0001: "USER_APPROVED",
    0x0002: "SANDBOXED",
    0x0100: "DOWNLOAD_INCOMPLETE",
}

_PRIVILEGED_LINUX_NAMESPACES = ("trusted.", "security.")
_SUSPICIOUS_KEY_SUBSTRINGS = (
    "payload",
    "loader",
    "shell",
    "exec",
    "backdoor",
    "implant",
    "stage",
    "beacon",
    "c2",
)
_KNOWN_BAD_KEYS = frozenset({"user.ai", "user.payload", "user.data"})
_EXECUTABLE_MAGICS = (
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "PE/DOS binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64 (LE)"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32 (LE)"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal/FAT"),
    (b"#!/", "script shebang"),
)

scan_errors = []
# Deliberate policy skips are tracked apart from failures: they must be
# disclosed so coverage is never overstated, but a symlink in the tree is not
# a scan error and must not drain the meaning of a nonzero exit status.
skipped_entries = []
_dropped_scan_errors = 0
_dropped_skipped_entries = 0
_last_files_scanned = 0
_files_seen = 0
_resource_limit_reached = False
_xattr_backend = None


class XattrLimitError(OSError):
    """Raised when an extended-attribute metadata list exceeds its limit."""


class SkippedEntry(OSError):
    """Raised when an entry is deliberately not scanned.

    Skips are recorded rather than swallowed. A forensic tool must never imply
    it examined an object it declined to open.
    """


class _BudgetExceeded(Exception):
    """Internal signal that a bounded render ran out of budget."""


class _RenderBudget:
    """Character, node, and depth budget for rendering hostile structures."""

    __slots__ = ("chars", "nodes", "exceeded")

    def __init__(self, chars, nodes):
        self.chars = chars
        self.nodes = nodes
        self.exceeded = False

    def spend(self, text):
        self.chars -= len(text)
        if self.chars < 0:
            self.exceeded = True
            raise _BudgetExceeded()
        return text

    def visit(self):
        self.nodes -= 1
        if self.nodes < 0:
            self.exceeded = True
            raise _BudgetExceeded()


class LibcXattrBackend:
    """Bounded, file-descriptor-based xattr reader for macOS and Linux."""

    def __init__(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.is_macos = sys.platform == "darwin"
        if not self.is_macos and not sys.platform.startswith("linux"):
            raise RuntimeError("XTT supports extended attributes on macOS and Linux only")

        self._flistxattr = self.libc.flistxattr
        self._fgetxattr = self.libc.fgetxattr
        if self.is_macos:
            self._flistxattr.argtypes = [
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_int,
            ]
            self._fgetxattr.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_uint32,
                ctypes.c_int,
            ]
        else:
            self._flistxattr.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
            self._fgetxattr.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
            ]
        self._flistxattr.restype = ctypes.c_ssize_t
        self._fgetxattr.restype = ctypes.c_ssize_t

    @staticmethod
    def _raise_last_error():
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, os.strerror(error_number))

    def _list_call(self, file_descriptor, buffer, size):
        ctypes.set_errno(0)
        if self.is_macos:
            result = self._flistxattr(file_descriptor, buffer, size, 0)
        else:
            result = self._flistxattr(file_descriptor, buffer, size)
        if result < 0:
            self._raise_last_error()
        return result

    def _get_call(self, file_descriptor, name, buffer, size):
        ctypes.set_errno(0)
        if self.is_macos:
            result = self._fgetxattr(file_descriptor, name, buffer, size, 0, 0)
        else:
            result = self._fgetxattr(file_descriptor, name, buffer, size)
        if result < 0:
            self._raise_last_error()
        return result

    def list_names(self, file_descriptor):
        for _ in range(XATTR_RETRIES):
            required = self._list_call(file_descriptor, None, 0)
            if required == 0:
                return []
            if required > MAX_XATTR_LIST_SIZE:
                raise XattrLimitError(
                    errno.E2BIG,
                    "extended-attribute name list exceeds {} bytes".format(
                        MAX_XATTR_LIST_SIZE
                    ),
                )
            buffer = ctypes.create_string_buffer(required)
            try:
                received = self._list_call(file_descriptor, buffer, required)
            except OSError as exc:
                if exc.errno == errno.ERANGE:
                    continue
                raise
            return [name for name in buffer.raw[:received].split(b"\0") if name]
        raise OSError(errno.EAGAIN, "extended-attribute list changed repeatedly")

    def read_value(self, file_descriptor, name):
        """Return (value, size, stored).

        ``stored`` is False when the value exceeded MAX_EA_SIZE and was read
        only to run detection. Neither the platform's ``fgetxattr`` nor a
        short buffer supports a partial read (both return ERANGE), so an
        oversized value is either read whole and discarded or not read at all.
        """
        for _ in range(XATTR_RETRIES):
            required = self._get_call(file_descriptor, name, None, 0)
            if required > MAX_EA_DETECT_SIZE:
                return None, required, False
            if required == 0:
                return b"", 0, True
            buffer = ctypes.create_string_buffer(required)
            try:
                received = self._get_call(file_descriptor, name, buffer, required)
            except OSError as exc:
                if exc.errno == errno.ERANGE:
                    continue
                raise
            return buffer.raw[:received], received, received <= MAX_EA_SIZE
        raise OSError(errno.EAGAIN, "extended attribute changed repeatedly")


def get_xattr_backend():
    global _xattr_backend
    if _xattr_backend is None:
        _xattr_backend = LibcXattrBackend()
    return _xattr_backend


def reset_scan_state():
    global _dropped_scan_errors, _dropped_skipped_entries
    global _last_files_scanned, _files_seen, _resource_limit_reached
    scan_errors.clear()
    skipped_entries.clear()
    _dropped_scan_errors = 0
    _dropped_skipped_entries = 0
    _last_files_scanned = 0
    _files_seen = 0
    _resource_limit_reached = False


def record_scan_error(path, attribute, operation, exc):
    global _dropped_scan_errors
    error = {
        "file_path": os.fsdecode(path),
        "attribute_key": os.fsdecode(attribute) if attribute else "",
        "operation": str(operation),
        "error": "{}: {}".format(type(exc).__name__, exc),
    }
    if len(scan_errors) < MAX_SCAN_ERRORS:
        scan_errors.append(error)
    else:
        _dropped_scan_errors += 1


def calculate_entropy(data):
    if not data:
        return 0
    data_len = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        probability = count / data_len
        entropy -= probability * math.log2(probability)
    return round(entropy, 2)


def _escape_nonprintable_characters(text):
    return "".join(
        char if char.isprintable() else "[U+{:04X}]".format(ord(char))
        for char in text
    )


def sanitize_for_terminal(value):
    """Neutralize control characters in every untrusted terminal field."""
    text = str(value)
    # str.isprintable() is a C-level check that is False for every category-C
    # character, so the common clean-string case skips the per-character scan.
    if text.isprintable():
        return text
    return _escape_nonprintable_characters(text)


def sanitize_for_csv(value):
    """Neutralize control characters, then force formula-like text to stay literal.

    Escaping runs first for two reasons: the CSV is the artifact analysts later
    cat/grep/less, so ANSI sequences must not survive into it, and surrogate
    escapes from os.fsdecode() would otherwise raise UnicodeEncodeError when the
    row is written to a UTF-8 handle.
    """
    text = str(value)
    if not text.isprintable():
        text = _escape_nonprintable_characters(text)
    index = 0
    while index < len(text) and text[index].isspace():
        index += 1
    if text[index : index + 1] in ("=", "+", "-", "@"):
        return "'" + text
    return text


def _bounded_content(text):
    if len(text) <= MAX_CONTENT_CHARS:
        return text
    omitted = len(text) - MAX_CONTENT_CHARS
    return "{}[TRUNCATED: {} characters omitted]".format(
        text[:MAX_CONTENT_CHARS], omitted
    )


def parse_quarantine(raw_value):
    """Decode a bounded com.apple.quarantine value without large integer parsing."""
    try:
        decoded = raw_value.decode("utf-8").strip()
    except UnicodeDecodeError:
        return "[QUARANTINE RAW] HEX:{}".format(raw_value.hex())

    parts = decoded.split(";", 3)
    if len(parts) < 2:
        return decoded

    flags_field = parts[0]
    timestamp_field = parts[1]
    if (
        len(flags_field) > MAX_QUARANTINE_HEX_CHARS
        or len(timestamp_field) > MAX_QUARANTINE_HEX_CHARS
    ):
        return "[QUARANTINE INVALID] numeric field exceeds parsing limit"

    try:
        flags_raw = int(flags_field, 16)
    except ValueError:
        return "[QUARANTINE RAW] {}".format(decoded)

    flag_names = [
        name for bit, name in QUARANTINE_FLAGS.items() if flags_raw & bit
    ]
    flag_text = "|".join(flag_names) if flag_names else "NONE"

    timestamp_text = timestamp_field
    if timestamp_field:
        try:
            timestamp = int(timestamp_field, 16) + 978307200
            timestamp_text = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.gmtime(timestamp)
            )
        except (OSError, OverflowError, ValueError):
            pass

    agent = parts[2] if len(parts) > 2 else ""
    identifier = parts[3] if len(parts) > 3 else ""
    return (
        "[QUARANTINE] flags={} ({}) | ts={} | agent={} | uuid={}".format(
            flag_text, flags_field, timestamp_text, agent, identifier
        )
    )


def _render_plist(obj, budget, depth=0):
    """Render a parsed plist under a hard node, depth, and output budget.

    plistlib resolves repeated object references to the same Python object, so
    parsing stays cheap while repr() re-expands every reference. Rendering must
    therefore be bounded independently of the input size.
    """
    budget.visit()
    if depth > MAX_PLIST_DEPTH:
        return budget.spend("[DEPTH LIMIT]")

    if isinstance(obj, dict):
        rendered = []
        for key, value in obj.items():
            rendered.append(
                "{}: {}".format(
                    _render_plist(key, budget, depth + 1),
                    _render_plist(value, budget, depth + 1),
                )
            )
        budget.spend("{}" + ", " * max(len(rendered) - 1, 0))
        return "{" + ", ".join(rendered) + "}"

    if isinstance(obj, (list, tuple)):
        rendered = [_render_plist(item, budget, depth + 1) for item in obj]
        budget.spend("[]" + ", " * max(len(rendered) - 1, 0))
        return "[" + ", ".join(rendered) + "]"

    if isinstance(obj, (bytes, bytearray)):
        head = bytes(obj[:MAX_PLIST_LEAF_BYTES])
        suffix = "..." if len(obj) > len(head) else ""
        return budget.spend("<{}{}>".format(head.hex(), suffix))

    if isinstance(obj, str):
        # Slice before repr() so a large leaf is never fully materialized.
        if len(obj) > MAX_PLIST_LEAF_CHARS:
            return budget.spend(repr(obj[:MAX_PLIST_LEAF_CHARS]) + "...")
        return budget.spend(repr(obj))

    text = repr(obj)
    if len(text) > MAX_PLIST_LEAF_CHARS:
        text = text[:MAX_PLIST_LEAF_CHARS] + "..."
    return budget.spend(text)


def decode_ea_content(attr_name, raw_value):
    """Decode quarantine, bounded binary plists, UTF-8, or binary hex."""
    if attr_name == "com.apple.quarantine":
        return _bounded_content(parse_quarantine(raw_value))

    if raw_value.startswith(b"bplist00") and len(raw_value) <= MAX_PLIST_SIZE:
        try:
            parsed = plistlib.loads(raw_value)
        except Exception:
            # plistlib processes hostile evidence. Any parser failure falls back
            # to a literal representation instead of aborting the scan.
            parsed = None
        else:
            budget = _RenderBudget(MAX_PLIST_RENDER_CHARS, MAX_PLIST_NODES)
            try:
                return _bounded_content("[BPLIST] {}".format(_render_plist(parsed, budget)))
            except _BudgetExceeded:
                return (
                    "[BPLIST TRUNCATED] structure exceeds render budget "
                    "({} chars / {} nodes / depth {})".format(
                        MAX_PLIST_RENDER_CHARS, MAX_PLIST_NODES, MAX_PLIST_DEPTH
                    )
                )
            except Exception:
                pass

    try:
        return _bounded_content(raw_value.decode("utf-8"))
    except UnicodeDecodeError:
        return _bounded_content("HEX:{}".format(raw_value.hex()))


def detect_findings(attr_name, raw_value):
    """Apply bounded T1564.014 triage rules without regex evaluation."""
    findings = []
    name_lower = (attr_name or "").lower()

    for namespace in _PRIVILEGED_LINUX_NAMESPACES:
        if name_lower.startswith(namespace):
            findings.append(
                "PRIV-NS: privileged namespace '{}'".format(namespace.rstrip("."))
            )
            break

    if name_lower in _KNOWN_BAD_KEYS:
        findings.append("KNOWN-KEY: attribute key matches known-abuse list")

    for token in _SUSPICIOUS_KEY_SUBSTRINGS:
        if token in name_lower:
            findings.append("SUSP-KEY: key contains '{}'".format(token))
            break

    if isinstance(raw_value, (bytes, bytearray)):
        prefix = bytes(raw_value[:4])
        for magic, label in _EXECUTABLE_MAGICS:
            if prefix.startswith(magic):
                findings.append("EXEC-MAGIC: value begins with {}".format(label))
                break

    return findings


def _open_flags():
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


def _open_verified(path, dir_fd=None, allow_directory=False):
    """Open a path as a verified regular file (or directory) without following links."""
    stat_kwargs = {"follow_symlinks": False}
    open_kwargs = {}
    if dir_fd is not None:
        stat_kwargs["dir_fd"] = dir_fd
        open_kwargs["dir_fd"] = dir_fd

    before = os.stat(path, **stat_kwargs)
    if stat.S_ISLNK(before.st_mode):
        raise SkippedEntry(errno.ELOOP, "symbolic link not scanned")
    if not stat.S_ISREG(before.st_mode) and not (
        allow_directory and stat.S_ISDIR(before.st_mode)
    ):
        # Opening device nodes on a live system has side effects (watchdogs
        # arm, tape devices rewind), so non-regular files are never opened.
        raise SkippedEntry(
            errno.EINVAL,
            "non-regular file not scanned (mode {:#o})".format(
                stat.S_IFMT(before.st_mode)
            ),
        )

    file_descriptor = os.open(path, _open_flags(), **open_kwargs)
    try:
        after = os.fstat(file_descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise OSError(errno.ESTALE, "file identity changed while opening")
        return file_descriptor, after
    except Exception:
        os.close(file_descriptor)
        raise


def record_skipped_entry(path, exc):
    global _dropped_skipped_entries
    entry = {
        "file_path": os.fsdecode(path),
        "reason": "{}".format(exc),
    }
    if len(skipped_entries) < MAX_SCAN_ERRORS:
        skipped_entries.append(entry)
    else:
        _dropped_skipped_entries += 1


def _record_open_failure(display_path, exc):
    """Record every unscanned entry so scan coverage is never overstated."""
    if isinstance(exc, SkippedEntry):
        record_skipped_entry(display_path, exc)
    else:
        record_scan_error(display_path, None, "open file", exc)


def _process_open_file(
    file_descriptor,
    file_stat,
    display_path,
    calc_entropy=False,
    skew_threshold_days=None,
    run_detect=False,
):
    results = []
    stored_bytes = 0
    readable_mtime = "N/A"
    is_skewed = False
    if skew_threshold_days is not None:
        readable_mtime = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(file_stat.st_mtime)
        )
        age_seconds = time.time() - file_stat.st_mtime
        is_skewed = age_seconds < (skew_threshold_days * 86400)

    backend = get_xattr_backend()
    try:
        names = backend.list_names(file_descriptor)
    except (OSError, RuntimeError) as exc:
        record_scan_error(display_path, None, "list attributes", exc)
        return results

    for name_bytes in names:
        if len(results) >= MAX_RESULTS:
            record_scan_error(
                display_path,
                None,
                "process attributes",
                XattrLimitError(errno.E2BIG, "per-file result-count limit reached"),
            )
            _set_resource_limit()
            break
        attr_name = os.fsdecode(name_bytes)
        try:
            raw_value, value_size, stored = backend.read_value(
                file_descriptor, name_bytes
            )
        except OSError as exc:
            record_scan_error(display_path, attr_name, "read attribute", exc)
            continue

        if raw_value is None:
            # Beyond MAX_EA_DETECT_SIZE nothing is read, so the detection gap is
            # declared in the output rather than passing an empty value to the
            # rules and silently reporting "no findings".
            content = (
                "[!] EA TOO LARGE ({} bytes, not read; content rules not applied)"
            ).format(value_size)
            entropy_score = "N/A"
            findings = detect_findings(attr_name, None) if run_detect else []
        elif not stored:
            # Read transiently for detection only, then discarded unstored.
            entropy_score = (
                calculate_entropy(raw_value[:MAX_ENTROPY_SAMPLE_BYTES])
                if calc_entropy
                else "N/A"
            )
            findings = detect_findings(attr_name, raw_value) if run_detect else []
            content = (
                "[!] EA TOO LARGE ({} bytes, not stored; scanned for detection"
                ", entropy sampled over first {} bytes)"
            ).format(value_size, min(value_size, MAX_ENTROPY_SAMPLE_BYTES))
            raw_value = None
        else:
            entropy_score = calculate_entropy(raw_value) if calc_entropy else "N/A"
            content = decode_ea_content(attr_name, raw_value)
            findings = detect_findings(attr_name, raw_value) if run_detect else []

        stored_size = (len(raw_value) if raw_value is not None else 0) + sys.getsizeof(
            content
        )
        if stored_bytes + stored_size > MAX_TOTAL_VALUE_BYTES:
            record_scan_error(
                display_path,
                attr_name,
                "process attribute",
                XattrLimitError(errno.E2BIG, "per-file stored-byte limit reached"),
            )
            _set_resource_limit()
            break

        results.append(
            {
                "file_path": os.fsdecode(display_path),
                "attribute_key": attr_name,
                "content": content,
                "entropy": entropy_score,
                "is_high_entropy": isinstance(entropy_score, float)
                and entropy_score > 7,
                "is_skewed": is_skewed,
                "mtime": readable_mtime,
                "detections": "; ".join(findings),
                "is_detected": bool(findings),
                "_stored_size": stored_size,
                "_value_size": value_size,
            }
        )
        stored_bytes += stored_size
    return results


def process_file(
    path, calc_entropy=False, skew_threshold_days=None, run_detect=False
):
    """Securely process a single path using one verified file descriptor."""
    global _last_files_scanned
    try:
        file_descriptor, file_stat = _open_verified(path)
    except OSError as exc:
        _record_open_failure(path, exc)
        return []

    _last_files_scanned += 1
    try:
        return _process_open_file(
            file_descriptor,
            file_stat,
            path,
            calc_entropy,
            skew_threshold_days,
            run_detect,
        )
    finally:
        os.close(file_descriptor)


def _process_file_at(
    name,
    directory_fd,
    display_path,
    calc_entropy=False,
    skew_threshold_days=None,
    run_detect=False,
):
    global _last_files_scanned
    try:
        file_descriptor, file_stat = _open_verified(name, dir_fd=directory_fd)
    except OSError as exc:
        _record_open_failure(display_path, exc)
        return []

    _last_files_scanned += 1
    try:
        return _process_open_file(
            file_descriptor,
            file_stat,
            display_path,
            calc_entropy,
            skew_threshold_days,
            run_detect,
        )
    finally:
        os.close(file_descriptor)


def collect_results(
    target, is_dir, calc_entropy=False, skew_threshold_days=None, run_detect=False
):
    """Collect bounded results and count files in the same traversal."""
    global _files_seen
    results = []
    total_value_bytes = 0
    stop = False

    def accept_entries(path, entries):
        """Store as many entries as the budget allows, then stop the scan.

        Partial acceptance matters: dropping a whole file's evidence because its
        last attribute crossed a limit would let one crafted file displace
        everything found after it.
        """
        nonlocal total_value_bytes, stop
        for entry in entries:
            entry_bytes = entry.get("_stored_size", 0)
            if len(results) + 1 > MAX_RESULTS:
                record_scan_error(
                    path,
                    None,
                    "store results",
                    XattrLimitError(errno.E2BIG, "result-count limit reached"),
                )
                _set_resource_limit()
                stop = True
                return
            if total_value_bytes + entry_bytes > MAX_TOTAL_VALUE_BYTES:
                record_scan_error(
                    path,
                    None,
                    "store results",
                    XattrLimitError(errno.E2BIG, "total attribute-byte limit reached"),
                )
                _set_resource_limit()
                stop = True
                return
            results.append(entry)
            total_value_bytes += entry_bytes

    if not is_dir:
        _files_seen = 1
        accept_entries(
            target,
            process_file(
                target, calc_entropy, skew_threshold_days, run_detect
            ),
        )
        return results

    def walk_error(exc):
        record_scan_error(getattr(exc, "filename", target), None, "walk directory", exc)

    try:
        root_fd, root_stat = _open_verified(target, allow_directory=True)
    except OSError as exc:
        record_scan_error(target, None, "open directory", exc)
        return results
    if not stat.S_ISDIR(root_stat.st_mode):
        os.close(root_fd)
        record_scan_error(
            target,
            None,
            "open directory",
            NotADirectoryError(errno.ENOTDIR, "target is not a directory"),
        )
        return results

    try:
        walker = os.fwalk(
            ".",
            topdown=True,
            onerror=walk_error,
            follow_symlinks=False,
            dir_fd=root_fd,
        )
        for root, directories, files, directory_fd in walker:
            relative_root = os.path.relpath(root, ".")
            display_root = (
                target
                if relative_root == "."
                else os.path.join(target, relative_root)
            )
            safe_directories = []
            for directory in directories:
                directory_path = os.path.join(display_root, directory)
                try:
                    mode = os.stat(
                        directory,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    ).st_mode
                    if stat.S_ISDIR(mode):
                        safe_directories.append(directory)
                    elif stat.S_ISLNK(mode):
                        record_skipped_entry(
                            directory_path,
                            SkippedEntry(
                                errno.ELOOP,
                                "symbolic-link directory not scanned",
                            ),
                        )
                    else:
                        record_skipped_entry(
                            directory_path,
                            SkippedEntry(
                                errno.EINVAL,
                                "non-directory traversal entry not scanned "
                                "(mode {:#o})".format(stat.S_IFMT(mode)),
                            ),
                        )
                except OSError as exc:
                    record_scan_error(
                        directory_path,
                        None,
                        "inspect directory",
                        exc,
                    )
            directories[:] = safe_directories

            for name in files:
                if _files_seen >= MAX_FILES:
                    record_scan_error(
                        display_root,
                        None,
                        "scan files",
                        XattrLimitError(errno.E2BIG, "file-count limit reached"),
                    )
                    _set_resource_limit()
                    stop = True
                    break
                display_path = os.path.join(display_root, name)
                _files_seen += 1
                accept_entries(
                    display_path,
                    _process_file_at(
                        name,
                        directory_fd,
                        display_path,
                        calc_entropy,
                        skew_threshold_days,
                        run_detect,
                    ),
                )
                if stop:
                    break
            if stop:
                break
    except OSError as exc:
        record_scan_error(target, None, "walk directory", exc)
    finally:
        os.close(root_fd)
    return results


def _set_resource_limit():
    global _resource_limit_reached
    _resource_limit_reached = True


def _use_color(stream):
    return bool(getattr(stream, "isatty", lambda: False)()) and "NO_COLOR" not in os.environ


def _render_field(value, limit=None):
    """Sanitize a field for display, truncating before the expensive escape."""
    text = str(value)
    if limit is not None and len(text) > limit:
        # Truncate first: escaping expands control characters eightfold, so a
        # multi-megabyte hostile value must never be expanded just to be cut.
        omitted = len(text) - limit
        return "{}[+{} chars truncated for display]".format(
            sanitize_for_terminal(text[:limit]), omitted
        )
    return sanitize_for_terminal(text)


def render_results(
    results, calc_entropy=False, check_skew=False, run_detect=False
):
    """Render sanitized evidence to the terminal."""
    path_width, mtime_width, key_width, entropy_width = 40, 20, 30, 7
    line_length = path_width + key_width + 16
    if check_skew:
        line_length += mtime_width + 3
    if calc_entropy:
        line_length += entropy_width + 3

    header = "\n{:<{}} | ".format("File Path", path_width)
    if check_skew:
        header += "{:<{}} | ".format("Last Modified (file)", mtime_width)
    header += "{:<{}}".format("Key", key_width)
    if calc_entropy:
        header += " | {:<{}}".format("Entropy", entropy_width)
    header += " | Content"
    print(header)
    print("-" * line_length)

    color_enabled = _use_color(sys.stdout)
    for entry in results:
        line = "{:<{}} | ".format(
            _render_field(entry["file_path"]), path_width
        )
        if check_skew:
            line += "{:<{}} | ".format(
                _render_field(entry["mtime"]), mtime_width
            )
        line += "{:<{}}".format(
            _render_field(entry["attribute_key"]), key_width
        )
        if calc_entropy:
            line += " | {:<{}}".format(entry["entropy"], entropy_width)
        line += " | {}".format(
            _render_field(entry["content"], MAX_RENDER_CONTENT_CHARS)
        )
        if run_detect and entry.get("is_detected"):
            line += "  <<< [T1564.014] {}".format(
                _render_field(entry["detections"])
            )

        color = ""
        if run_detect and entry.get("is_detected"):
            color = MAGENTA
        elif entry.get("is_high_entropy"):
            color = RED
        elif entry.get("is_skewed"):
            color = YELLOW
        print("{}{}{}".format(color, line, RESET) if color and color_enabled else line)
    print("-" * line_length)


def summarize_results(
    results, files_scanned, calc_entropy=False, check_skew=False, run_detect=False
):
    """Print scan statistics and an explicit incomplete-scan report."""
    files_with_attributes = len({entry["file_path"] for entry in results})
    summary = "Summary: Examined: {} | w/ EA: {}".format(
        files_scanned, files_with_attributes
    )
    skipped_count = len(skipped_entries) + _dropped_skipped_entries
    if skipped_count:
        summary += " | Skipped (symlink/non-regular): {}".format(skipped_count)
    if calc_entropy:
        summary += " | High Entropy (>7): {}".format(
            sum(1 for entry in results if entry.get("is_high_entropy"))
        )
    if check_skew:
        skewed_files = len(
            {entry["file_path"] for entry in results if entry.get("is_skewed")}
        )
        summary += (
            " | Files w/ Recent mtime: {} [NOTE: mtime != EA write time]".format(
                skewed_files
            )
        )
    if run_detect:
        detected_attributes = sum(
            1 for entry in results if entry.get("is_detected")
        )
        detected_files = len(
            {entry["file_path"] for entry in results if entry.get("is_detected")}
        )
        summary += " | T1564.014 Detections: {} attr / {} file(s)".format(
            detected_attributes, detected_files
        )
    print(summary)
    print("-" * 80)

    if skipped_count:
        # Not an error, but coverage the analyst must see: these objects were
        # never examined, and on macOS a symlink can itself carry attributes.
        print(
            "[i] {} entr(ies) deliberately not scanned:".format(skipped_count),
            file=sys.stderr,
        )
        for entry in skipped_entries:
            print(
                "    {} | {}".format(
                    sanitize_for_terminal(entry["file_path"]),
                    sanitize_for_terminal(entry["reason"]),
                ),
                file=sys.stderr,
            )
        if _dropped_skipped_entries:
            print(
                "    {} additional skip(s) omitted by reporting limit".format(
                    _dropped_skipped_entries
                ),
                file=sys.stderr,
            )

    error_count = len(scan_errors) + _dropped_scan_errors
    if error_count:
        print(
            "[!] Scan incomplete: {} file/attribute operation(s) failed.".format(
                error_count
            ),
            file=sys.stderr,
        )
        for error in scan_errors:
            fields = (
                error["file_path"],
                error["attribute_key"],
                error["operation"],
                error["error"],
            )
            print(
                "    " + " | ".join(sanitize_for_terminal(field) for field in fields),
                file=sys.stderr,
            )
        if _dropped_scan_errors:
            print(
                "    {} additional error(s) omitted by reporting limit".format(
                    _dropped_scan_errors
                ),
                file=sys.stderr,
            )


def _csv_fieldnames(calc_entropy=False, check_skew=False, run_detect=False):
    fields = ["file_path"]
    if check_skew:
        fields.append("mtime")
    fields.extend(["attribute_key", "content"])
    if calc_entropy:
        fields.append("entropy")
    if run_detect:
        fields.append("detections")
    return fields


def export_results(
    results, output_file, calc_entropy=False, check_skew=False, run_detect=False
):
    """Create a new permission-restricted CSV without following output symlinks."""
    if not results:
        print("[!] No results to export.")
        return False

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    file_descriptor = os.open(output_file, flags, 0o600)
    fieldnames = _csv_fieldnames(calc_entropy, check_skew, run_detect)
    completed = False
    try:
        with os.fdopen(file_descriptor, "w", newline="", encoding="utf-8") as handle:
            file_descriptor = -1
            writer = csv.DictWriter(
                handle, fieldnames=fieldnames, extrasaction="ignore"
            )
            writer.writeheader()
            for row in results:
                writer.writerow(
                    {
                        field: sanitize_for_csv(row.get(field, ""))
                        for field in fieldnames
                    }
                )
        completed = True
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        if not completed:
            # A partial report must not be left behind looking like a complete one.
            try:
                os.unlink(output_file)
            except OSError:
                pass
    print("[+] Report exported to: {}".format(sanitize_for_terminal(output_file)))
    return True


def positive_finite_float(value):
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return parsed


def build_parser():
    parser = argparse.ArgumentParser(
        description="XTT: Extended Attribute Triage Tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="XTT {}".format(VERSION))
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-d", "--directory", help="Recursive scan of a directory.")
    target_group.add_argument("-f", "--file", help="Scan a single file.")
    parser.add_argument(
        "-e", "--entropy", action="store_true", help="Calculate Shannon entropy per EA."
    )
    parser.add_argument(
        "-t",
        "--time-skew",
        action="store_true",
        help=(
            "Flag files whose mtime is within --skew-days (default: 3). "
            "This is file mtime, not EA write time."
        ),
    )
    parser.add_argument(
        "--skew-days",
        type=positive_finite_float,
        default=3.0,
        metavar="N",
        help="Threshold in days for --time-skew (default: 3).",
    )
    parser.add_argument(
        "--detect",
        action="store_true",
        help="Run static T1564.014 extended-attribute detection rules.",
    )
    parser.add_argument(
        "-w", "--write", metavar="OUTPUT.csv", help="Create a new CSV report."
    )
    return parser


def _validate_target(parser, target, is_dir):
    try:
        target_stat = os.stat(target, follow_symlinks=False)
    except OSError as exc:
        parser.error("cannot access target: {}".format(sanitize_for_terminal(exc)))
    if stat.S_ISLNK(target_stat.st_mode):
        parser.error("symbolic-link targets are not accepted")
    if is_dir and not stat.S_ISDIR(target_stat.st_mode):
        parser.error("--directory target is not a directory")
    if not is_dir and stat.S_ISDIR(target_stat.st_mode):
        parser.error("--file target is a directory")


def _validate_output_path(parser, output_file, target, is_dir):
    if os.path.lexists(output_file):
        parser.error("output path already exists; refusing to overwrite it")
    # realpath() resolves aliases in existing parent directories even though the
    # output itself does not exist yet. commonpath() avoids unsafe string-prefix
    # checks such as /evidence matching /evidence-old.
    output_path = os.path.realpath(output_file)
    target_path = os.path.realpath(target)
    if output_path == target_path:
        parser.error("output path must differ from the evidence path")
    if is_dir:
        try:
            inside_target = (
                os.path.commonpath((target_path, output_path)) == target_path
            )
        except ValueError:
            inside_target = False
        if inside_target:
            # Writing the report into the tree under examination contaminates it.
            parser.error("output path must not be inside the evidence directory")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    target = args.directory if args.directory is not None else args.file
    is_dir = args.directory is not None
    _validate_target(parser, target, is_dir)

    if args.write:
        _validate_output_path(parser, args.write, target, is_dir)

    reset_scan_state()
    skew_days = args.skew_days if args.time_skew else None
    results = collect_results(
        target, is_dir, args.entropy, skew_days, args.detect
    )
    render_results(results, args.entropy, args.time_skew, args.detect)
    summarize_results(
        results,
        _last_files_scanned,
        args.entropy,
        args.time_skew,
        args.detect,
    )

    if args.write:
        try:
            export_results(
                results, args.write, args.entropy, args.time_skew, args.detect
            )
        except (OSError, ValueError) as exc:
            # ValueError covers UnicodeEncodeError, which OSError alone missed.
            print(
                "Error: unable to create CSV report: {}".format(
                    sanitize_for_terminal(exc)
                ),
                file=sys.stderr,
            )
            return 2

    return (
        2
        if scan_errors or _dropped_scan_errors or _resource_limit_reached
        else 0
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        try:
            sys.stdout.close()
        finally:
            sys.exit(1)

























































































































































































































































































































































































































































































































































































































































































































































































# Dedicado para minha esposa Taise e meus filhos Pietro e Matteo
