"""Cryptex core — the tool registry.

Everything in Cryptex is a Tool.  A Tool declares what it is, what it needs,
and what it does, and the interface is generated from that declaration, so
adding a new encoder/decoder means writing one function and one @register
block and nothing else.
"""
from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# --------------------------------------------------------------------------
# Parameter and result types
# --------------------------------------------------------------------------

KINDS = ("text", "password", "int", "float", "choice", "bool",
         "file", "files", "folder", "savefile", "multiline")


@dataclass
class Param:
    """One control on the tool's settings row."""
    name: str                       # keyword argument passed to the function
    label: str                      # what the user sees
    kind: str = "text"
    default: Any = None
    choices: Optional[list] = None
    help: str = ""                  # tooltip / hint under the control
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    filetypes: Optional[list] = None
    width: int = 18
    only: str = "both"              # "encode", "decode" or "both"
    # Optional: fn(current values) -> bool. Settings that do not apply to the
    # choices already made are hidden rather than left to confuse.
    visible_when: Optional[Callable] = None


@dataclass
class Result:
    """What a tool hands back.  Anything not set is simply not shown."""
    text: str = ""
    data: Optional[bytes] = None          # binary payload (offered as Save)
    image_path: Optional[str] = None      # rendered in the preview pane
    file_path: Optional[str] = None       # a file written on disk
    rows: Optional[list] = None           # [(col, col, ...), ...] table
    headers: Optional[list] = None
    note: str = ""                        # green status line
    warn: str = ""                        # amber status line
    suggested_name: str = ""
    # "auto" shows an image if there is one, else a table, else the text.
    # "text" forces the text to the front and prints any rows beneath it,
    # which is what a live decoder wants: the message matters, the signal
    # details are supporting information.
    prefer: str = "auto"

    def __post_init__(self):
        # tools often write `warn=None if all is well else "..."`, which reads
        # naturally and would otherwise hand the interface a None where every
        # caller expects a string
        self.note = self.note or ""
        self.warn = self.warn or ""
        self.text = self.text or ""
        self.suggested_name = self.suggested_name or ""


def as_result(value) -> Result:
    if isinstance(value, Result):
        return value
    if isinstance(value, bytes):
        try:
            return Result(text=value.decode("utf-8"))
        except UnicodeDecodeError:
            return Result(text=pretty_hex(value), data=value,
                          note="Binary output — shown as hex, use Save to keep the real bytes.")
    return Result(text="" if value is None else str(value))


@dataclass
class Tool:
    id: str
    name: str
    category: str
    summary: str                       # one line, shown in the sidebar
    explain: str = ""                  # plain-English "what is this"
    example: str = ""                  # a worked example
    security: str = ""                 # caution bar, shown in amber
    encode: Optional[Callable] = None
    decode: Optional[Callable] = None
    action: Optional[Callable] = None  # single-direction tools (hashes, keygen)
    # A streaming tool is a generator: stream(stop_event, **params) yields a
    # Result every time it has something new to show, and returns when the
    # stop event is set. The interface turns it into Start / Stop buttons.
    stream: Optional[Callable] = None
    params: list = field(default_factory=list)
    input_kind: str = "text"           # "text", "file", "folder", "none"
    input_label: str = "Input"
    input_types: Optional[list] = None  # file-dialog filters, e.g. [("Audio", "*.wav")]
    encode_label: str = "Encode"
    decode_label: str = "Decode"
    action_label: str = "Run"
    start_label: str = "Start listening"
    stop_label: str = "Stop"
    tags: list = field(default_factory=list)
    binary_ok: bool = False            # accepts raw bytes rather than text

    def directions(self):
        out = []
        if self.encode:
            out.append(("encode", self.encode_label, self.encode))
        if self.decode:
            out.append(("decode", self.decode_label, self.decode))
        if self.action:
            out.append(("action", self.action_label, self.action))
        return out

    def params_for(self, direction):
        return [p for p in self.params
                if p.only == "both"
                or p.only == direction
                or (direction == "action" and p.only == "encode")]


# --------------------------------------------------------------------------
# The registry
# --------------------------------------------------------------------------

REGISTRY: dict[str, Tool] = {}

# The order the categories appear in, which is also the order they make sense
# to learn in: work out what you have, then decode it, then the real crypto.
CATEGORY_ORDER = ["Identify", "Encodings", "Classical ciphers", "Analysis",
                  "Encryption", "Hashing", "Keys & certificates",
                  "Interop", "Tokens & secrets", "Steganography", "Forensics & OSINT", "Signals"]


def register(tool: Tool) -> Tool:
    if tool.id in REGISTRY:
        raise ValueError(f"duplicate tool id: {tool.id}")
    REGISTRY[tool.id] = tool
    if tool.category not in CATEGORY_ORDER:
        CATEGORY_ORDER.append(tool.category)   # anything new goes on the end
    return tool


def tool(**kwargs) -> Tool:
    """Shorthand: register(tool(...))."""
    return register(Tool(**kwargs))


def all_tools():
    return list(REGISTRY.values())


def by_category():
    out = {}
    for t in REGISTRY.values():
        out.setdefault(t.category, []).append(t)
    for v in out.values():
        v.sort(key=lambda t: t.name.lower())
    return out


def search(term: str):
    term = (term or "").strip().lower()
    if not term:
        return all_tools()
    hits = []
    for t in REGISTRY.values():
        hay = " ".join([t.name, t.summary, t.category, " ".join(t.tags), t.explain]).lower()
        if term in hay:
            hits.append(t)
    return hits


# --------------------------------------------------------------------------
# Shared helpers used all over the tool modules
# --------------------------------------------------------------------------

class ToolError(Exception):
    """Raised for anything the user did wrong — shown as a friendly message."""


def clamp(value, low, high, default=None):
    """Keep a number inside the range a tool can actually use.

    The settings boxes do not stop you typing 0 or -1, and several libraries
    answer that with a raw ValueError rather than anything readable.
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = int(default if default is not None else low)
    return max(low, min(high, n))


def need(value, message):
    if value in (None, "", b""):
        raise ToolError(message)
    return value


def to_bytes(data) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    return str(data).encode("utf-8")


def to_text(data) -> str:
    if isinstance(data, (bytes, bytearray)):
        return bytes(data).decode("utf-8", errors="replace")
    return str(data)


def pretty_hex(data: bytes, width: int = 16) -> str:
    data = to_bytes(data)
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart:<{width*3-1}}  |{asc}|")
    return "\n".join(lines)


def clean_ws(text: str) -> str:
    return "".join(text.split())


def b64_any(text: str) -> bytes:
    """Decode base64 tolerantly — url-safe, missing padding, embedded whitespace."""
    s = clean_ws(text).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise ToolError(f"That is not valid Base64 ({exc}).") from exc


def strip_non_alpha(text: str) -> str:
    """Keep only A-Z and a-z.

    `str.isalpha()` is true for É, Ω, and several thousand other characters,
    which is right for text and wrong for a 26-letter cipher - it walks
    straight into an index error the moment someone pastes an accent.
    """
    return "".join(c for c in text if "a" <= c <= "z" or "A" <= c <= "Z")


def is_ascii_letter(c: str) -> bool:
    return "a" <= c <= "z" or "A" <= c <= "Z"


ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def sniff_format(text: str) -> str:
    """Guess how a blob of text is written: "hex", "base64" or "text".

    Used wherever a tool would otherwise make you say which it is.
    Deliberately cautious - it only claims hex or Base64 when the shape is
    unambiguous, because guessing wrong is worse than asking.
    """
    body = clean_ws(str(text))
    if len(body) < 8:
        return "text"
    hx = body.lower().replace("0x", "")
    if len(hx) >= 8 and len(hx) % 2 == 0 and all(c in "0123456789abcdef" for c in hx):
        return "hex"
    b64 = body.replace("-", "+").replace("_", "/")
    if len(b64) >= 16 and all(c.isalnum() or c in "+/=" for c in b64):
        kinds = (any(c.isdigit() for c in b64) + any(c.isupper() for c in b64)
                 + any(c.islower() for c in b64))
        if b64.endswith("=") or (len(b64) % 4 == 0 and kinds == 3):
            try:
                base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=True)
                return "base64"
            except Exception:
                pass
    return "text"


def decode_as(text, how: str):
    """Turn text into bytes according to `how` ("auto", "hex", "base64",
    "text"). Returns (bytes, the format actually used)."""
    how = (how or "auto").lower()
    if how in ("auto", "detect"):
        how = sniff_format(to_text(text))
    if how == "hex":
        s = clean_ws(to_text(text)).lower().replace("0x", "")
        digits = "".join(c for c in s if c in "0123456789abcdef")
        if not digits or len(digits) % 2:
            raise ToolError("That is not valid hex - it needs an even number of "
                            "hex digits (0-9, a-f). Set the format by hand if it "
                            "is really text.")
        return bytes.fromhex(digits), "hex"
    if how == "base64":
        return b64_any(to_text(text)), "base64"
    return to_bytes(text), "text"


# --------------------------------------------------------------------------
# Where the app keeps its settings
# --------------------------------------------------------------------------

def app_dir() -> str:
    """The folder to write settings and logs into.

    Beside the executable when frozen; on macOS beside the .app rather than
    inside it, because writing inside a signed bundle breaks the signature.
    """
    import sys
    if getattr(sys, "frozen", False):
        exe = os.path.abspath(sys.executable)
        parts = exe.split(os.sep)
        for i, p in enumerate(parts):
            if p.endswith(".app"):
                return os.sep.join(parts[:i]) or os.sep
        return os.path.dirname(exe)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resource_dir() -> str:
    """Where bundled read-only resources live inside a frozen build."""
    import sys
    return getattr(sys, "_MEIPASS", app_dir())


def settings_path() -> str:
    return os.path.join(app_dir(), "cryptex-settings.json")


def downloads_dir() -> str:
    """The user's Downloads folder, or home if there is no such folder."""
    home = os.path.expanduser("~")
    if os.name == "nt":
        # Downloads can be moved in Windows; ask the shell where it really is
        try:
            import ctypes
            from ctypes import wintypes

            class GUID(ctypes.Structure):
                _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                            ("Data3", wintypes.WORD), ("Data4", wintypes.BYTE * 8)]

            fid = GUID(0x374DE290, 0x123F, 0x4565,        # FOLDERID_Downloads
                       (wintypes.BYTE * 8)(0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B))
            out = ctypes.c_wchar_p()
            if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(fid), 0, None,
                                                         ctypes.byref(out)) == 0:
                found = out.value
                ctypes.windll.ole32.CoTaskMemFree(out)
                if found and os.path.isdir(found):
                    return found
        except Exception:
            pass
    cand = os.path.join(home, "Downloads")
    return cand if os.path.isdir(cand) else home


def default_save_dir() -> str:
    """Where anything the user asks Cryptex to write goes by default: the
    folder chosen under File > Default save folder, else Downloads."""
    try:
        import json
        with open(settings_path(), encoding="utf-8") as fh:
            chosen = json.load(fh).get("save_dir")
        if chosen and os.path.isdir(chosen):
            return chosen
    except Exception:
        pass
    return downloads_dir()
