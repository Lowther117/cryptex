"""Steganography - hiding things in plain sight, and finding them again.

Encryption makes a message unreadable. Steganography makes it unnoticed. The
two are not rivals: the sensible thing is to encrypt first and hide second, so
that finding the hiding place still leaves you with nothing.

What is here:

* **Least-significant-bit images.** The bottom bit of a colour value is the
  difference between red 200 and red 201, which no eye can see, so it is free
  space. A 1920x1080 photograph has about 780,000 of those bits going spare -
  roughly 97 KB - and changing them all leaves the picture looking identical.
* **Bit planes.** The same idea used backwards, to look for other people's
  hidden data. A photograph's bottom bit is camera noise and looks like grey
  static; a bottom bit carrying a message looks like structure.
* **Zero-width characters.** Text can hide text. There are Unicode characters
  that occupy no space and print nothing, and a run of them between two
  ordinary words survives copy and paste through most chat apps and documents.
* **Carving.** Most file formats say where they end, and most readers stop
  there, so anything appended afterwards is invisible to the program but still
  sitting in the file. This finds it.
* **Metadata.** Photographs carry the camera, the date, the settings and often
  the GPS position of where they were taken. Worth seeing before you post one.
"""
from __future__ import annotations

import os
import struct

from .core import (Param, Result, ToolError, clamp, need, to_bytes, to_text,
                   tool)

CAT = "Steganography"

MAGIC = b"CXS1"
Z0 = "​"      # zero-width space          -> bit 0
Z1 = "‌"      # zero-width non-joiner     -> bit 1
ZEND = "‍"    # zero-width joiner         -> end marker
ZALL = Z0 + Z1 + ZEND + "﻿⁠"


def _pil():
    try:
        from PIL import Image
        return Image
    except ImportError:
        raise ToolError("This needs Pillow. Install it with:  pip install pillow")


def _np():
    try:
        import numpy
        return numpy
    except ImportError:
        raise ToolError("This needs numpy. Install it with:  pip install numpy")


IMAGE_TYPES = [("Images", "*.png *.bmp *.tif *.tiff *.jpg *.jpeg *.webp *.gif"),
               ("All files", "*.*")]
LOSSLESS_TYPES = [("Lossless images", "*.png *.bmp *.tif *.tiff"),
                  ("All files", "*.*")]


# --------------------------------------------------------------------------
# Payload wrapping, shared by the image and text hiding
# --------------------------------------------------------------------------

def _wrap(message, password) -> bytes:
    body = to_bytes(message)
    if not body:
        raise ToolError("There is nothing to hide - type a message first.")
    flags = 0
    if password:
        from .modern import _aead, _derive, _pack
        salt, nonce = os.urandom(16), os.urandom(12)
        key, meta = _derive(password, salt, "scrypt", 4)
        meta["cipher"] = "aes-256-gcm"
        meta["v"] = 1
        body = _pack(meta, salt, nonce,
                     _aead(key, "AES-256-GCM").encrypt(nonce, body, None))
        flags = 1
    return MAGIC + bytes([flags]) + struct.pack("<I", len(body)) + body


def _unwrap(raw: bytes, password) -> bytes:
    if not raw.startswith(MAGIC):
        raise ToolError("No hidden message found here. Either there is nothing "
                        "hidden, or it was hidden by something other than Cryptex.")
    flags = raw[4]
    n = struct.unpack_from("<I", raw, 5)[0]
    body = raw[9:9 + n]
    if len(body) < n:
        raise ToolError("The hidden message is cut short - the file has been "
                        "re-saved, cropped or recompressed since it was hidden.")
    if flags & 1:
        need(password, "This hidden message is encrypted. Type the password.")
        from .modern import _aead, _rederive, _unpack
        meta, salt, nonce, ct = _unpack(body)
        key = _rederive(password, salt, meta)
        try:
            body = _aead(key, meta.get("cipher", "aes-256-gcm")).decrypt(nonce, ct, None)
        except Exception:
            raise ToolError("Wrong password - or the message has been altered.")
    return body


def _as_text(body: bytes) -> tuple[str, bytes]:
    try:
        return body.decode("utf-8"), b""
    except UnicodeDecodeError:
        return "", body


# --------------------------------------------------------------------------
# Least-significant-bit images
# --------------------------------------------------------------------------

def _load_rgb(path):
    Image = _pil()
    np = _np()
    path = need(path, "Pick an image to work with.")
    if not os.path.isfile(path):
        raise ToolError(f"Not a file: {path}")
    try:
        img = Image.open(path)
        img.load()
    except Exception as exc:
        raise ToolError(f"Could not read that image: {exc}")
    keep_alpha = img.mode in ("RGBA", "LA", "PA")
    alpha = img.convert("RGBA").getchannel("A") if keep_alpha else None
    arr = np.array(img.convert("RGB"), dtype=np.uint8)
    return arr, alpha, img


def _capacity(arr, bits):
    return arr.size * bits // 8


def _lsb_hide(path, message="", password="", bits=1, outdir=""):
    np = _np()
    Image = _pil()
    bits = int(clamp(bits, 1, 4, 1))
    arr, alpha, img = _load_rgb(path)
    payload = _wrap(message, password)
    room = _capacity(arr, bits)
    if len(payload) > room:
        raise ToolError(
            f"That message needs {len(payload):,} bytes and this image has room for "
            f"{room:,} at {bits} bit per channel. Use a larger image, raise the bits "
            "per channel (2 is still invisible in a photograph), or shorten the message.")

    flat = arr.reshape(-1)
    unpacked = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    per = bits
    pad = (-len(unpacked)) % per
    if pad:
        unpacked = np.concatenate([unpacked, np.zeros(pad, dtype=np.uint8)])
    groups = unpacked.reshape(-1, per)
    values = np.zeros(len(groups), dtype=np.uint8)
    for i in range(per):
        values = (values << 1) | groups[:, i]
    mask = np.uint8(0xFF ^ ((1 << per) - 1))
    n = len(values)
    flat[:n] = (flat[:n] & mask) | values

    out = Image.fromarray(arr.reshape(img.size[1], img.size[0], 3), "RGB")
    if alpha is not None:
        out.putalpha(alpha)
    base = os.path.splitext(os.path.basename(path))[0]
    folder = outdir or os.path.dirname(os.path.abspath(path))
    dest = os.path.join(folder, base + " [hidden].png")
    i = 2
    while os.path.exists(dest):
        dest = os.path.join(folder, f"{base} [hidden {i}].png")
        i += 1
    out.save(dest, "PNG")
    used = 100.0 * len(payload) / room
    return Result(file_path=dest, image_path=dest,
                  rows=[("Hidden", f"{len(payload):,} bytes"),
                        ("Capacity", f"{room:,} bytes"),
                        ("Used", f"{used:.1f}% of the space"),
                        ("Bits per channel", bits),
                        ("Encrypted", "yes" if password else "no"),
                        ("Saved to", dest)],
                  headers=["", ""],
                  note=f"Written to {dest}. It must stay a PNG - "
                       "saving it as a JPEG throws the message away.",
                  warn=None if password else
                       "Hidden, but not encrypted. Anyone who thinks to look will read it. "
                       "Set a password to encrypt it first.")


def _lsb_extract(path, password="", bits=0, outdir=""):
    np = _np()
    arr, _alpha, _img = _load_rgb(path)
    flat = arr.reshape(-1)
    tries = [int(bits)] if bits else [1, 2, 3, 4]
    last = None
    for per in tries:
        take = min(len(flat), 9 * 8 // per + 64)
        try:
            head = _read_bits(np, flat[:take], per, 9)
        except Exception:
            continue
        if not head.startswith(MAGIC):
            continue
        n = struct.unpack_from("<I", head, 5)[0]
        want = 9 + n
        if want * 8 > len(flat) * per:
            last = "the length in the header is larger than the image can hold"
            continue
        raw = _read_bits(np, flat[:(want * 8 + per - 1) // per], per, want)
        body = _unwrap(raw, password)
        text, data = _as_text(body)
        return Result(text=text, data=data or None,
                      suggested_name="hidden.bin" if data else "",
                      rows=[("Found", f"{n:,} bytes"),
                            ("Bits per channel", per),
                            ("Encrypted", "yes" if raw[4] & 1 else "no")],
                      headers=["", ""], prefer="text",
                      note=f"Recovered {n:,} bytes hidden at {per} bit per channel.")
    raise ToolError(
        "No Cryptex message found in this image"
        + (f" ({last})" if last else "")
        + ". If you expected one: it has to be the lossless copy - a JPEG, a "
          "screenshot, or anything a chat app has recompressed will have lost it. "
          "To look for someone else's hidden data instead, try the bit-plane viewer.")


def _read_bits(np, flat, per, nbytes):
    """Pull nbytes out of the bottom `per` bits of each channel value."""
    need_bits = nbytes * 8
    count = (need_bits + per - 1) // per
    vals = flat[:count].astype(np.uint8)
    out = np.zeros(count * per, dtype=np.uint8)
    for i in range(per):
        out[i::per] = (vals >> (per - 1 - i)) & 1
    return np.packbits(out[:need_bits]).tobytes()


tool(id="lsb-hide", name="Hide a message in an image", category=CAT,
     summary="Writes text into the bottom bits of a picture's colours",
     explain=(
         "Every pixel of a photograph is three numbers from 0 to 255. Changing the last "
         "bit of one moves it by one step out of 256 - invisible on a screen, invisible in "
         "print, invisible next to the original. So the bottom bit of every colour value "
         "in the picture is free storage, and a 12-megapixel photograph has about four and "
         "a half megabytes of it.\n\n"
         "Give it a password and the message is encrypted with AES-256-GCM before it goes "
         "in, which is the right way round: someone who suspects the picture and goes "
         "looking still finds nothing readable.\n\n"
         "The result is always saved as a PNG, and it has to stay one. JPEG works by "
         "throwing away detail the eye will not miss, and the bottom bits are exactly the "
         "detail it throws away. The same goes for anything that recompresses on upload - "
         "most chat apps, most social networks. Send the file itself, not the picture."),
     example="Pick a photo, type a message, set a password, and send the PNG it writes.",
     tags=["steganography", "lsb", "hide", "image", "png", "conceal"],
     input_kind="file", input_label="Cover image", input_types=IMAGE_TYPES,
     params=[Param("message", "Message to hide", "multiline", "", width=48),
             Param("password", "Password (optional)", "password", "", width=24,
                   help="Encrypts the message before hiding it. Strongly advised."),
             Param("bits", "Bits per colour", "int", 1, minimum=1, maximum=4,
                   help="1 is undetectable by eye. 2 doubles the room and is still "
                        "safe in a photograph. 4 starts to show in flat areas."),
             Param("outdir", "Save into", "folder", "",
                   help="Leave empty to save beside the original.")],
     action=_lsb_hide, action_label="Hide it")


tool(id="lsb-extract", name="Read a message from an image", category=CAT,
     summary="Pulls a hidden message back out of a picture",
     explain=(
         "The other half of the hiding tool. It reads the bottom bits back, checks for the "
         "marker Cryptex writes, and hands you what was put in - decrypting it first if a "
         "password was used.\n\n"
         "It tries one, two, three and four bits per channel automatically, so you do not "
         "have to remember which was used.\n\n"
         "If nothing is found, the usual reason is that the picture has been through "
         "something that re-encoded it. Hidden data survives copying the file; it does not "
         "survive a screenshot, a JPEG save, or most upload pipelines."),
     tags=["steganography", "lsb", "extract", "reveal", "image"],
     input_kind="file", input_label="Image to examine", input_types=IMAGE_TYPES,
     params=[Param("password", "Password", "password", "", width=24,
                   help="Only needed if the message was encrypted."),
             Param("bits", "Bits per colour", "int", 0, minimum=0, maximum=4,
                   help="0 tries them all, which is almost always what you want.")],
     action=_lsb_extract, action_label="Read it")


# --------------------------------------------------------------------------
# Bit planes - looking for other people's hidden data
# --------------------------------------------------------------------------

def _bitplane(path, plane=0, channel="all", outdir=""):
    np = _np()
    Image = _pil()
    arr, _alpha, img = _load_rgb(path)
    plane = int(clamp(plane, 0, 7, 0))
    if channel == "red":
        sel = arr[:, :, 0]
    elif channel == "green":
        sel = arr[:, :, 1]
    elif channel == "blue":
        sel = arr[:, :, 2]
    else:
        sel = None

    if sel is None:
        bits = ((arr >> plane) & 1).astype(np.uint8) * 255
        pic = Image.fromarray(bits, "RGB")
    else:
        bits = ((sel >> plane) & 1).astype(np.uint8) * 255
        pic = Image.fromarray(bits, "L")

    base = os.path.splitext(os.path.basename(path))[0]
    folder = outdir or os.path.dirname(os.path.abspath(path))
    dest = os.path.join(folder, f"{base} [bit {plane} {channel}].png")
    pic.save(dest, "PNG")

    # how random does the bottom bit look? camera noise is close to fifty-fifty
    # and has no structure; a message is closer still, but a drawing is not
    low = (arr & 1).astype(np.uint8)
    ones = float(low.mean())
    runs = float(np.mean(low[:, 1:, :] == low[:, :-1, :]))
    if plane == 0:
        if abs(ones - 0.5) < 0.01 and abs(runs - 0.5) < 0.02:
            verdict = ("The bottom bit is almost perfectly random, which is what both "
                       "camera noise and hidden data look like. Look at the picture.")
        elif abs(ones - 0.5) > 0.08 or runs > 0.7:
            verdict = ("The bottom bit is far from random - it follows the picture. "
                       "This looks like an ordinary image with nothing hidden in it.")
        else:
            verdict = "The bottom bit is fairly random. Not conclusive either way."
    else:
        verdict = ""

    return Result(image_path=dest, file_path=dest,
                  rows=[("Plane", f"bit {plane} ({'lowest' if plane == 0 else 'highest' if plane == 7 else 'middle'})"),
                        ("Channel", channel),
                        ("Ones in the bottom bit", f"{ones:.3f} (0.500 is random)"),
                        ("Neighbours that agree", f"{runs:.3f} (0.500 is random)"),
                        ("Saved to", dest)],
                  headers=["", ""],
                  note=verdict or f"Bit {plane} of {channel} written to {dest}.")


tool(id="bitplane", name="Bit-plane viewer", category=CAT,
     summary="Shows one bit of a picture on its own - where hidden data shows up",
     explain=(
         "A way of seeing what is in a picture that you cannot see in the picture.\n\n"
         "Each colour value is eight bits. The top bits carry the image - shapes, edges, "
         "faces. The bottom bit carries almost nothing: in a photograph it is sensor noise, "
         "and on its own it looks like grey static. That makes it the obvious place to hide "
         "something, and it makes this the obvious way to check.\n\n"
         "Pull out bit 0 and look. Static means noise, or well-hidden encrypted data. "
         "Blocks, edges, a band of solid black partway down, or readable text mean somebody "
         "has been here. In a drawing, a logo or a screenshot the bottom bit is not noisy "
         "at all - large flat areas of colour have identical bottom bits - so structure "
         "there is normal and proves nothing.\n\n"
         "The two numbers underneath are a quick sanity check: how often the bottom bit is "
         "a one, and how often it matches its neighbour. Both sit near 0.500 for noise and "
         "for hidden data, and well away from it for flat artwork."),
     tags=["steganography", "bitplane", "forensics", "detect", "image", "lsb"],
     input_kind="file", input_label="Image to examine", input_types=IMAGE_TYPES,
     params=[Param("plane", "Bit to show", "int", 0, minimum=0, maximum=7,
                   help="0 is the bottom bit, where things get hidden. 7 is the top."),
             Param("channel", "Colour", "choice", "all",
                   choices=["all", "red", "green", "blue"]),
             Param("outdir", "Save into", "folder", "")],
     action=_bitplane, action_label="Show the plane")


# --------------------------------------------------------------------------
# Zero-width characters in text
# --------------------------------------------------------------------------

def _zw_hide(data, cover="", password="", position="end"):
    payload = _wrap(data, password)
    bits = "".join(f"{b:08b}" for b in payload)
    hidden = "".join(Z1 if c == "1" else Z0 for c in bits) + ZEND
    cover = to_text(cover)
    if not cover.strip():
        raise ToolError("Type some ordinary cover text for the hidden message to live in.")
    if position == "start":
        out = hidden + cover
    elif position == "after first word":
        parts = cover.split(" ", 1)
        out = parts[0] + hidden + (" " + parts[1] if len(parts) > 1 else "")
    else:
        out = cover + hidden
    return Result(text=out,
                  rows=[("Hidden", f"{len(payload):,} bytes"),
                        ("Invisible characters added", f"{len(hidden):,}"),
                        ("Encrypted", "yes" if password else "no"),
                        ("Visible length", f"{len(cover):,} characters")],
                  headers=["", ""], prefer="text",
                  note="Copy the whole block. It looks exactly like the cover text "
                       "because the difference prints as nothing.",
                  warn="Anything that strips formatting or normalises Unicode - some "
                       "forums, some email clients - will silently remove it.")


def _zw_extract(data, password="", **_k):
    text = to_text(data)
    bits = "".join("1" if c == Z1 else "0" for c in text if c in (Z0, Z1))
    if not bits:
        raise ToolError("No zero-width characters in this text, so there is nothing "
                        "hidden in it - at least not this way.")
    raw = bytes(int(bits[i:i + 8].ljust(8, "0"), 2) for i in range(0, len(bits), 8))
    body = _unwrap(raw, password)
    txt, blob = _as_text(body)
    return Result(text=txt, data=blob or None,
                  rows=[("Invisible characters", f"{sum(1 for c in text if c in ZALL):,}"),
                        ("Recovered", f"{len(body):,} bytes")],
                  headers=["", ""], prefer="text",
                  note=f"Recovered {len(body):,} bytes from between the visible letters.")


tool(id="zero-width", name="Hide text inside text", category=CAT,
     summary="Uses invisible Unicode characters to carry a message inside ordinary writing",
     explain=(
         "Unicode has characters that take no space and draw nothing: the zero-width space, "
         "the zero-width non-joiner, the joiner. They exist for typesetting languages where "
         "letters join up, and they are perfectly legal in ordinary text.\n\n"
         "Two of them are enough to spell out bits, so any message can be written as a run "
         "of nothing and dropped into a sentence. What you see is the cover text. What you "
         "copy is the cover text plus the message, and it survives being pasted into most "
         "chat apps, documents and code comments.\n\n"
         "Set a password and the message is encrypted first.\n\n"
         "Two warnings. It does not survive anything that normalises or strips Unicode, "
         "which some forums and mail clients do. And it is easy to spot if anyone thinks to "
         "look - the character count will not match what is on the screen."),
     example="Cover: 'Lunch at one?'  Hidden: 'bring the keys'",
     tags=["steganography", "zero width", "unicode", "invisible", "text", "hide"],
     params=[Param("cover", "Cover text", "multiline", "", width=48, only="encode",
                   help="The ordinary, visible text the message will live inside."),
             Param("password", "Password (optional)", "password", "", width=24),
             Param("position", "Put it", "choice", "end", only="encode",
                   choices=["end", "start", "after first word"])],
     encode=_zw_hide, decode=_zw_extract,
     encode_label="Hide", decode_label="Reveal")


# --------------------------------------------------------------------------
# Carving: things appended to, or buried in, a file
# --------------------------------------------------------------------------

SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG image", ".png", b"IEND\xaeB`\x82"),
    (b"\xff\xd8\xff", "JPEG image", ".jpg", b"\xff\xd9"),
    (b"GIF89a", "GIF image", ".gif", b"\x00;"),
    (b"GIF87a", "GIF image", ".gif", b"\x00;"),
    (b"BM", "BMP image", ".bmp", None),
    (b"%PDF-", "PDF document", ".pdf", b"%%EOF"),
    (b"PK\x03\x04", "ZIP archive (or docx/xlsx/pptx/jar/apk)", ".zip", None),
    (b"Rar!\x1a\x07", "RAR archive", ".rar", None),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", ".7z", None),
    (b"\x1f\x8b\x08", "gzip", ".gz", None),
    (b"\xfd7zXZ\x00", "xz", ".xz", None),
    (b"OggS", "Ogg media", ".ogg", None),
    (b"fLaC", "FLAC audio", ".flac", None),
    (b"ID3", "MP3 audio", ".mp3", None),
    (b"RIFF", "RIFF (WAV or AVI)", ".wav", None),
    (b"\x00\x00\x01\xba", "MPEG program stream", ".mpg", None),
    (b"MZ", "Windows executable", ".exe", None),
    (b"\x7fELF", "Linux executable", ".elf", None),
    (b"\xca\xfe\xba\xbe", "Java class or Mach-O fat binary", ".bin", None),
    (b"SQLite format 3\x00", "SQLite database", ".db", None),
    (b"-----BEGIN ", "PEM key or certificate", ".pem", None),
]


def _container_end(raw):
    """Where the file's own format says it stops, if it says at all."""
    for magic, _name, _ext, end in SIGNATURES:
        if raw.startswith(magic) and end:
            at = raw.rfind(end)
            if at >= 0:
                return at + len(end)
    if raw.startswith(b"PK\x03\x04"):
        at = raw.rfind(b"PK\x05\x06")
        if at >= 0 and at + 22 <= len(raw):
            comment = struct.unpack_from("<H", raw, at + 20)[0]
            return at + 22 + comment
    return None


def _carve(path, extract=False, outdir="", minimum=64):
    path = need(path, "Pick a file to examine.")
    if not os.path.isfile(path):
        raise ToolError(f"Not a file: {path}")
    raw = open(path, "rb").read()
    if not raw:
        raise ToolError("That file is empty.")
    rows, found, warn = [], [], None

    end = _container_end(raw)
    if end is not None and end < len(raw):
        extra = len(raw) - end
        rows.append(("Appended data", f"{extra:,} bytes after the file's proper end"))
        found.append((end, len(raw), "appended data", ".bin"))
        warn = (f"{extra:,} bytes are sitting past the end of this file. Every normal "
                "program stops at the end marker and never sees them. This is the "
                "oldest trick there is - and often a ZIP.")
    elif end is not None:
        rows.append(("Appended data", "none - the file ends where it says it does"))

    for magic, name, ext, _e in SIGNATURES:
        start = 0
        while True:
            at = raw.find(magic, start)
            if at < 0:
                break
            start = at + 1
            if at == 0:
                rows.append(("This file is", name))
                continue
            if len(raw) - at < minimum or len(magic) < 4:
                continue   # two-byte markers match by chance far too often
            rows.append((f"Embedded at {at:,}", name))
            found.append((at, len(raw), name, ext))
            if len(found) > 40:
                break

    written = []
    if extract and found:
        folder = outdir or os.path.dirname(os.path.abspath(path))
        base = os.path.splitext(os.path.basename(path))[0]
        for i, (at, stop, name, ext) in enumerate(found[:20], 1):
            dest = os.path.join(folder, f"{base} [carved {i}]{ext}")
            with open(dest, "wb") as fh:
                fh.write(raw[at:stop])
            written.append(dest)
            rows.append((f"Written {i}", dest))

    if not rows:
        rows.append(("Result", "nothing unusual - no trailing data, nothing embedded"))
    return Result(rows=rows, headers=["Where", "What"],
                  note=(f"Carved {len(written)} file(s) out." if written else
                        f"{len(found)} thing(s) worth a look." if found else
                        "Nothing hidden found by signature."),
                  warn=warn)


tool(id="carve", name="Find files hidden inside files", category=CAT,
     summary="Spots data appended to, or buried inside, any file",
     explain=(
         "Almost every file format carries an end marker, and almost every program that "
         "reads one stops there. A PNG ends at IEND, a JPEG at FFD9, a PDF at %%EOF. "
         "Anything written after that point is still in the file, still takes up disk "
         "space, and is completely invisible to the viewer.\n\n"
         "That is why 'cat photo.png secret.zip > out.png' works, and has worked for thirty "
         "years: the picture still opens, and the archive still unzips.\n\n"
         "This checks for exactly that, then sweeps the whole file for the opening bytes of "
         "around twenty common formats, so a ZIP or a JPEG buried in the middle of "
         "something else shows up too. Tick the box and it will write each find out as its "
         "own file.\n\n"
         "Short markers are only trusted at the very start of the file, because two or "
         "three matching bytes happen by chance inside compressed data all the time. "
         "Something appended past the end marker is not chance."),
     tags=["steganography", "carve", "forensics", "appended", "embedded", "polyglot", "zip"],
     input_kind="file", input_label="File to examine",
     params=[Param("extract", "Write out what it finds", "bool", False),
             Param("outdir", "Save into", "folder", "",
                   visible_when=lambda v: bool(v.get("extract"))),
             Param("minimum", "Ignore finds smaller than", "int", 64,
                   minimum=8, maximum=100000, help="Bytes. Cuts down chance matches.")],
     action=_carve, action_label="Look inside")


# --------------------------------------------------------------------------
# Metadata
# --------------------------------------------------------------------------

def _exif(path, strip=False, outdir=""):
    Image = _pil()
    path = need(path, "Pick an image.")
    if not os.path.isfile(path):
        raise ToolError(f"Not a file: {path}")
    try:
        img = Image.open(path)
        img.load()
    except Exception as exc:
        raise ToolError(f"Could not read that image: {exc}")

    from PIL.ExifTags import GPSTAGS, TAGS
    rows = [("Format", f"{img.format}  {img.size[0]} x {img.size[1]}  {img.mode}")]
    exif = None
    try:
        exif = img.getexif()
    except Exception:
        exif = None
    gps_note = ""
    if exif:
        for tag, value in exif.items():
            name = TAGS.get(tag, f"Tag {tag}")
            if name == "GPSInfo":
                continue
            rows.append((name, _short(value)))
        try:
            gps = exif.get_ifd(0x8825)
        except Exception:
            gps = None
        if gps:
            for tag, value in gps.items():
                rows.append(("GPS " + GPSTAGS.get(tag, str(tag)), _short(value)))
            pos = _latlon(gps)
            if pos:
                rows.append(("GPS position", f"{pos[0]:.6f}, {pos[1]:.6f}"))
                gps_note = (f"This picture records where it was taken: {pos[0]:.6f}, "
                            f"{pos[1]:.6f}. Strip it before posting.")
    for k, v in (img.info or {}).items():
        if k in ("exif", "icc_profile", "xmp"):
            rows.append((k, f"{len(v):,} bytes"))
        elif isinstance(v, (str, int, float)):
            rows.append((k, _short(v)))

    warn = gps_note or None
    if strip:
        folder = outdir or os.path.dirname(os.path.abspath(path))
        base = os.path.splitext(os.path.basename(path))[0]
        ext = ".png" if img.format == "PNG" else ".jpg"
        dest = os.path.join(folder, f"{base} [clean]{ext}")
        clean = Image.new(img.mode, img.size)
        clean.putdata(list(img.getdata()))
        if ext == ".jpg" and clean.mode not in ("RGB", "L"):
            clean = clean.convert("RGB")       # JPEG cannot carry alpha or a palette
        clean.save(dest, quality=95) if ext == ".jpg" else clean.save(dest)
        rows.append(("Clean copy", dest))
        return Result(rows=rows, headers=["Field", "Value"], file_path=dest,
                      note=f"A copy with no metadata at all written to {dest}.",
                      warn=warn)
    if len(rows) == 1:
        rows.append(("Metadata", "none - this file carries no EXIF or text chunks"))
    return Result(rows=rows, headers=["Field", "Value"],
                  note=f"{len(rows) - 1} field(s) of metadata.", warn=warn)


def _short(v, n=90):
    if isinstance(v, bytes):
        return f"{len(v):,} bytes"
    s = str(v)
    return s if len(s) <= n else s[:n] + "..."


def _latlon(gps):
    def deg(t):
        return float(t[0]) + float(t[1]) / 60 + float(t[2]) / 3600
    try:
        lat = deg(gps[2]) * (-1 if str(gps[1]).upper().startswith("S") else 1)
        lon = deg(gps[4]) * (-1 if str(gps[3]).upper().startswith("W") else 1)
        return lat, lon
    except Exception:
        return None


tool(id="exif", name="Image metadata", category=CAT,
     summary="Shows the camera, date and GPS position buried in a photograph - and removes them",
     explain=(
         "A photograph is not only a photograph. Cameras and phones write a block of "
         "metadata into the file: make and model, lens, shutter speed, the date and time to "
         "the second, the serial number on some bodies, and - if location was on - the "
         "latitude and longitude to within a few metres.\n\n"
         "None of that is visible when you look at the picture, and all of it travels with "
         "the file. It is how people are routinely located by photographs they posted "
         "themselves.\n\n"
         "This shows you everything that is in there, and will write you a copy with all of "
         "it removed. Most social networks strip metadata on upload; sending the file "
         "directly, by email or chat, does not."),
     tags=["exif", "metadata", "gps", "privacy", "camera", "strip", "photo"],
     input_kind="file", input_label="Image", input_types=IMAGE_TYPES,
     params=[Param("strip", "Write a clean copy", "bool", False),
             Param("outdir", "Save into", "folder", "",
                   visible_when=lambda v: bool(v.get("strip")))],
     action=_exif, action_label="Read metadata")


# --------------------------------------------------------------------------
# Audio steganography - LSB in a WAV
# --------------------------------------------------------------------------

def _audio_hide(path, message="", password="", outdir="", **_k):
    np = _np()
    import wave
    path = need(path, "Pick a WAV file to hide the message inside.")
    if not os.path.isfile(path):
        raise ToolError(f"Not a file: {path}")
    try:
        with wave.open(path, "rb") as w:
            params = w.getparams()
            frames = w.readframes(w.getnframes())
    except Exception as exc:
        raise ToolError(f"Could not read that WAV: {exc}. This needs a plain PCM .wav - "
                        "convert an mp3 or m4a first.")
    if params.sampwidth != 2:
        raise ToolError("This works on 16-bit PCM WAV files (the usual kind). Re-export the "
                        "audio as 16-bit and try again.")
    samples = np.frombuffer(frames, dtype="<i2").copy()
    payload = _wrap(message, password)
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    if len(bits) > len(samples):
        raise ToolError(f"That message needs {len(bits):,} samples and this clip only has "
                        f"{len(samples):,}. Use a longer recording or a shorter message.")
    samples[:len(bits)] = (samples[:len(bits)] & ~1) | bits
    base = os.path.splitext(os.path.basename(path))[0]
    folder = outdir or os.path.dirname(os.path.abspath(path))
    dest = os.path.join(folder, base + " [hidden].wav")
    i = 2
    while os.path.exists(dest):
        dest = os.path.join(folder, f"{base} [hidden {i}].wav"); i += 1
    with wave.open(dest, "wb") as w:
        w.setparams(params)
        w.writeframes(samples.astype("<i2").tobytes())
    secs = params.nframes / params.framerate
    return Result(file_path=dest,
                  rows=[("Hidden", f"{len(payload):,} bytes"),
                        ("Capacity", f"{len(samples)//8:,} bytes"),
                        ("Clip length", f"{secs:.1f} s"),
                        ("Encrypted", "yes" if password else "no"),
                        ("Saved to", dest)],
                  headers=["", ""],
                  note=f"Written to {dest}. It sounds identical - the change is the bottom "
                       "bit of each sample. It must stay a WAV; re-encoding to MP3 destroys it.",
                  warn=None if password else
                       "Hidden but not encrypted. Set a password to encrypt it first.")


def _audio_extract(path, password="", **_k):
    np = _np()
    import wave
    path = need(path, "Pick the WAV to read.")
    if not os.path.isfile(path):
        raise ToolError(f"Not a file: {path}")
    try:
        with wave.open(path, "rb") as w:
            width = w.getsampwidth()
            frames = w.readframes(w.getnframes())
    except Exception as exc:
        raise ToolError(f"Could not read that WAV: {exc}")
    if width != 2:
        raise ToolError("This reads 16-bit PCM WAV files.")
    samples = np.frombuffer(frames, dtype="<i2")
    bits = (samples & 1).astype(np.uint8)
    # header is 9 bytes; read enough to learn the length, then the rest
    head = np.packbits(bits[:9 * 8]).tobytes()
    if not head.startswith(MAGIC):
        raise ToolError("No hidden Cryptex message in this WAV. If you expected one, it may "
                        "have been re-encoded (MP3/AAC) since - the bottom bits are lost when "
                        "that happens.")
    n = struct.unpack_from("<I", head, 5)[0]
    total = 9 + n
    body = np.packbits(bits[:total * 8]).tobytes()
    out = _unwrap(body, password)
    text, blob = _as_text(out)
    return Result(text=text, data=blob or None, suggested_name="hidden.bin" if blob else "",
                  rows=[("Found", f"{n:,} bytes"), ("Encrypted", "yes" if head[4] & 1 else "no")],
                  headers=["", ""], prefer="text",
                  note=f"Recovered {n:,} bytes from the audio.")


tool(id="audio-hide", name="Hide a message in audio", category=CAT,
     summary="Writes text into the bottom bit of each WAV sample",
     explain=(
         "The audio version of the image LSB tool. A 16-bit sample is a number from -32768 to "
         "32767; flipping its bottom bit changes the level by one part in 65,536, far below "
         "anything you can hear. So the bottom bit of every sample is spare, and a few minutes "
         "of CD-quality audio hides tens of kilobytes.\n\n"
         "Set a password and the message is encrypted with AES-256-GCM before it goes in. The "
         "result is a WAV and must stay one - MP3, AAC and Ogg all work by discarding exactly "
         "the inaudible detail the message lives in, so re-encoding wipes it.\n\n"
         "Give it a plain 16-bit PCM WAV; convert other formats to that first."),
     tags=["steganography", "audio", "wav", "lsb", "hide", "sound"],
     input_kind="file", input_label="Cover WAV (16-bit PCM)",
     input_types=[("WAV audio", "*.wav"), ("All files", "*.*")],
     params=[Param("message", "Message to hide", "multiline", "", width=48),
             Param("password", "Password (optional)", "password", "", width=24),
             Param("outdir", "Save into", "folder", "")],
     action=_audio_hide, action_label="Hide it")


tool(id="audio-extract", name="Read a message from audio", category=CAT,
     summary="Pulls a hidden message back out of a WAV",
     explain=(
         "Reads the bottom bits of a WAV back out, checks for the Cryptex marker, and hands "
         "you what was hidden - decrypting it if a password was used.\n\n"
         "If it finds nothing, the usual reason is that the file has been converted to a "
         "compressed format since the message went in."),
     tags=["steganography", "audio", "wav", "lsb", "extract"],
     input_kind="file", input_label="WAV to examine",
     input_types=[("WAV audio", "*.wav"), ("All files", "*.*")],
     params=[Param("password", "Password", "password", "", width=24)],
     action=_audio_extract, action_label="Read it")


# --------------------------------------------------------------------------
# Whitespace steganography - trailing spaces and tabs
# --------------------------------------------------------------------------

def _ws_hide(data, cover="", password="", **_k):
    payload = _wrap(data, password)
    bits = "".join(f"{b:08b}" for b in payload)
    cover = to_text(cover)
    lines = cover.split("\n") if cover.strip() else []
    if not lines:
        raise ToolError("Type some ordinary cover text - a few lines - for the hidden bits "
                        "to trail off the end of.")
    # 3 bits per line: pack into trailing spaces/tabs (tab=1, space=0), grouped
    per_line = 8
    chunks = [bits[i:i + per_line] for i in range(0, len(bits), per_line)]
    need_lines = len(chunks)
    while len(lines) < need_lines:
        lines.append("")
    out = []
    for i, line in enumerate(lines):
        base = line.rstrip()
        if i < len(chunks):
            trail = "".join("\t" if b == "1" else " " for b in chunks[i])
            out.append(base + trail)
        else:
            out.append(base)
    text = "\n".join(out)
    return Result(text=text,
                  rows=[("Hidden", f"{len(payload):,} bytes"),
                        ("Lines used", need_lines),
                        ("Encrypted", "yes" if password else "no")],
                  headers=["", ""], prefer="text",
                  note="The message is in the invisible spaces and tabs at the end of each "
                       "line. Copy the whole block exactly - most editors keep trailing "
                       "whitespace, but some strip it on save.",
                  warn="Anything that trims trailing whitespace - many code editors, some "
                       "chat apps - erases it silently.")


def _ws_extract(data, password="", **_k):
    text = to_text(data)
    bits = ""
    for line in text.split("\n"):
        stripped = line.rstrip(" \t")
        trail = line[len(stripped):]
        for ch in trail:
            if ch == "\t":
                bits += "1"
            elif ch == " ":
                bits += "0"
    if not bits:
        raise ToolError("No trailing spaces or tabs found, so there is nothing hidden this "
                        "way. (Whitespace at the end of lines is easy to lose - if you pasted "
                        "this from somewhere, it may have been trimmed.)")
    raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
    out = _unwrap(raw, password)
    txt, blob = _as_text(out)
    return Result(text=txt, data=blob or None,
                  rows=[("Recovered", f"{len(out):,} bytes")], headers=["", ""],
                  prefer="text", note=f"Recovered {len(out):,} bytes from the whitespace.")


tool(id="whitespace", name="Hide text in whitespace", category=CAT,
     summary="Buries a message in the trailing spaces and tabs of ordinary text",
     explain=(
         "Every line of text can carry a few invisible bits after its last visible character, "
         "as a run of spaces and tabs. Nobody sees them, and they survive being pasted into a "
         "lot of places that would strip the zero-width Unicode trick.\n\n"
         "Cryptex encodes the message as tabs (for 1) and spaces (for 0) trailing each line of "
         "your cover text, adding blank lines if it needs more room. Set a password to encrypt "
         "first.\n\n"
         "The catch is the same as its strength: trailing whitespace is invisible, so it is "
         "also easy to destroy. Code editors set to trim on save, and some forums, will wipe "
         "it. Keep the carrier somewhere that leaves it alone."),
     example="Cover: a few lines of an innocent-looking email.",
     tags=["steganography", "whitespace", "snow", "tabs", "spaces", "text", "hide"],
     params=[Param("cover", "Cover text", "multiline", "", width=48, only="encode",
                   help="A few lines of ordinary text to hide the message in."),
             Param("password", "Password (optional)", "password", "", width=24)],
     encode=_ws_hide, decode=_ws_extract,
     encode_label="Hide", decode_label="Reveal")


# --------------------------------------------------------------------------
# Stego detection - chi-square test for LSB embedding in an image
# --------------------------------------------------------------------------

def _stego_detect(path, **_k):
    np = _np()
    arr, _alpha, _img = _load_rgb(path)
    flat = arr.reshape(-1).astype(np.int64)

    # chi-square on "pairs of values" (PoV): LSB embedding equalises the counts
    # within each pair (2k, 2k+1). A clean image has very unequal pairs.
    hist = np.bincount(flat, minlength=256)
    even = hist[0::2].astype(np.float64)
    odd = hist[1::2].astype(np.float64)
    expected = (even + odd) / 2.0
    mask = expected > 4
    chi = float(np.sum((even[mask] - expected[mask]) ** 2 / expected[mask]))
    dof = int(mask.sum())

    # LSB ratio and neighbour agreement, as in the bit-plane tool
    low = (arr & 1).astype(np.uint8)
    ones = float(low.mean())
    runs = float(np.mean(low[:, 1:, :] == low[:, :-1, :]))

    # how much of the image, scanned from the top, looks embedded? sample windows
    embedded_like = abs(ones - 0.5) < 0.02 and abs(runs - 0.5) < 0.03
    chi_flat = dof > 0 and chi / max(1, dof) < 1.0

    if embedded_like and chi_flat:
        verdict = ("Strong signs of hidden data. The value pairs are unusually balanced and "
                   "the bottom bit is near-perfectly random across the whole image - which is "
                   "what LSB embedding does and ordinary photos do not.")
        level = "warn"
    elif embedded_like or chi_flat:
        verdict = ("Possible hidden data, or just a very noisy photo. One of the two tests "
                   "fired but not both. Open the bottom bit in the bit-plane viewer and look.")
        level = "warn"
    else:
        verdict = ("Looks clean. The value pairs are uneven and the bottom bit follows the "
                   "picture, both normal for an ordinary image with nothing hidden in it.")
        level = "note"

    rows = [("Chi-square / d.o.f.", f"{chi / max(1, dof):.2f}  (near 0 = suspicious)"),
            ("Bottom-bit ones", f"{ones:.4f}  (0.5000 = random)"),
            ("Neighbours agree", f"{runs:.4f}  (0.5000 = random)"),
            ("Verdict", "hidden data likely" if level == "warn" else "probably clean")]
    return Result(rows=rows, headers=["Measure", "Value"],
                  note=verdict if level == "note" else "",
                  warn=verdict if level == "warn" else "")


tool(id="stego-detect", name="Detect image steganography", category=CAT,
     summary="Chi-square and bit tests for whether an image is hiding LSB data",
     explain=(
         "The bit-plane viewer shows you the bottom bit; this puts a number on it. It runs the "
         "classic chi-square 'pairs of values' test - LSB embedding forces the counts of each "
         "even value and its odd neighbour towards equal, which almost never happens by "
         "chance in a real photo - alongside the same randomness checks the bit-plane tool "
         "reports.\n\n"
         "When both fire, it says data is likely hidden. When neither does, it says clean. "
         "The honest middle case - one test firing - it reports as 'possible', because a very "
         "noisy photograph and a stego image can look alike, and it points you at the "
         "bit-plane viewer to judge with your own eyes.\n\n"
         "It detects the tell-tale statistics of LSB embedding. It does not extract - if it "
         "was hidden with the Cryptex image tool, the 'Read a message from an image' tool "
         "pulls it out."),
     tags=["steganography", "detect", "chi-square", "forensics", "lsb", "stegexpose"],
     input_kind="file", input_label="Image to test", input_types=IMAGE_TYPES,
     action=_stego_detect, action_label="Test the image")
