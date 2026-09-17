"""Representation changes — same information, different alphabet.

Nothing in here is secret.  Every one of these is reversible by anybody.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import quopri
import re
import unicodedata
import urllib.parse

from .core import (ALPHA, Param, Result, ToolError, b64_any, clean_ws,
                   need, pretty_hex, to_bytes, to_text, tool)

CAT = "Encodings"

# --------------------------------------------------------------------------
# Base-N families
# --------------------------------------------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big") if data else 0
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = len(data) - len(data.lstrip(b"\0"))
    return "1" * pad + (out or ("" if data else ""))


def b58decode(text: str) -> bytes:
    s = clean_ws(text)
    n = 0
    for ch in s:
        if ch not in B58:
            raise ToolError(f"'{ch}' is not a Base58 character.")
        n = n * 58 + B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\0" * pad + body


tool(id="base64", name="Base64", category=CAT,
     summary="The everyday way to carry binary through text-only channels",
     explain=("Base64 rewrites any data using only 64 safe characters (A–Z, a–z, 0–9, + and /), "
              "padding the end with '='. It makes data about a third bigger and hides nothing — "
              "it exists so that binary survives email, JSON, URLs and copy-paste.\n\n"
              "You will meet it in email attachments, data: URLs, JWTs, API keys, config files "
              "and just about every 'encrypted-looking' string that turns out not to be."),
     example="Hello  ->  SGVsbG8=",
     tags=["b64", "mime", "base", "jwt"],
     params=[Param("urlsafe", "URL-safe alphabet", "bool", False,
                   help="Uses - and _ instead of + and /, as JWTs and URLs do.", only="encode"),
             Param("wrap", "Wrap at N characters", "int", 0,
                   help="0 = one long line. 76 is the MIME/email convention.", only="encode")],
     encode=lambda d, urlsafe=False, wrap=0: _b64_enc(d, urlsafe, wrap),
     decode=lambda d, **k: b64_any(to_text(d)),
     binary_ok=True)


def _b64_enc(data, urlsafe, wrap):
    raw = to_bytes(data)
    out = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(raw).decode()
    wrap = int(wrap or 0)
    if wrap > 0:
        out = "\n".join(out[i:i + wrap] for i in range(0, len(out), wrap))
    return out


tool(id="base32", name="Base32", category=CAT,
     summary="Case-insensitive base — TOTP secrets, onion addresses",
     explain=("Base32 uses A–Z and 2–7 only. It is bigger than Base64 but survives "
              "case-insensitive systems and is readable over the phone, which is why "
              "two-factor authenticator secrets and Tor addresses use it."),
     example="Hello  ->  JBSWY3DP",
     tags=["totp", "2fa", "rfc4648"],
     encode=lambda d, **k: base64.b32encode(to_bytes(d)).decode(),
     decode=lambda d, **k: _b32_dec(to_text(d)),
     binary_ok=True)


def _b32_dec(text):
    s = clean_ws(text).upper()
    s += "=" * (-len(s) % 8)
    try:
        return base64.b32decode(s)
    except (binascii.Error, ValueError) as exc:
        raise ToolError(f"Not valid Base32 ({exc}). Base32 uses A-Z and 2-7 only.") from exc


tool(id="base16", name="Base16 / Hex", category=CAT,
     summary="Two hex digits per byte — the plainest possible view of data",
     explain=("Every byte becomes two characters, 00 to ff. It doubles the size but it is "
              "completely unambiguous, which is why hashes, MAC addresses, colour codes and "
              "memory dumps are all written this way."),
     example="Hello  ->  48656c6c6f",
     tags=["hex", "hexadecimal"],
     params=[Param("sep", "Separator", "choice", "none",
                   choices=["none", "space", "colon", "0x, "], only="encode"),
             Param("upper", "Upper case", "bool", False, only="encode")],
     encode=lambda d, sep="none", upper=False: _hex_enc(d, sep, upper),
     decode=lambda d, **k: _hex_dec(to_text(d)),
     binary_ok=True)


def _hex_enc(data, sep, upper):
    raw = to_bytes(data)
    parts = [f"{b:02x}" for b in raw]
    if upper:
        parts = [p.upper() for p in parts]
    return {"none": "", "space": " ", "colon": ":", "0x, ": ", "}.get(sep, "").join(
        (("0x" + p) if sep == "0x, " else p) for p in parts)


def _hex_dec(text):
    s = text.lower().replace("0x", "")
    s = "".join(c for c in s if c in "0123456789abcdef")
    if len(s) % 2:
        raise ToolError("Hex needs an even number of digits — one pair per byte.")
    return bytes.fromhex(s)


tool(id="base85", name="Base85 / Ascii85", category=CAT,
     summary="Denser than Base64 — PDF, git binary patches",
     explain=("Base85 packs four bytes into five characters instead of Base64's four-into-six, "
              "so it is about 7% smaller. PDF uses the Ascii85 flavour; git and Python use the "
              "slightly different Base85 alphabet."),
     example="Hello  ->  87cURD] (Ascii85)",
     tags=["a85", "ascii85", "z85"],
     params=[Param("flavour", "Flavour", "choice", "Ascii85",
                   choices=["Ascii85", "Base85 (RFC1924/b85)"])],
     encode=lambda d, flavour="Ascii85": (base64.a85encode(to_bytes(d)) if flavour.startswith("Ascii")
                                          else base64.b85encode(to_bytes(d))).decode(),
     decode=lambda d, flavour="Ascii85": _b85_dec(to_text(d), flavour),
     binary_ok=True)

def _b85_dec(text, flavour):
    body = clean_ws(text)
    if not body:
        raise ToolError("Nothing to decode.")
    try:
        return (base64.a85decode(body) if flavour.startswith("Ascii")
                else base64.b85decode(body))
    except (binascii.Error, ValueError) as exc:
        raise ToolError(f"Not valid {flavour} ({exc}).") from exc


tool(id="base58", name="Base58", category=CAT,
     summary="Bitcoin's base — no 0, O, I or l to misread",
     explain=("Base58 is Base62 with the four characters people confuse by eye removed "
              "(zero, capital O, capital I, lower L) and no + or / so it survives double-click "
              "selection. Bitcoin addresses, IPFS hashes and many short links use it."),
     tags=["bitcoin", "btc", "ipfs"],
     encode=lambda d, **k: b58encode(to_bytes(d)),
     decode=lambda d, **k: b58decode(to_text(d)),
     binary_ok=True)

# --------------------------------------------------------------------------
# Web / transport encodings
# --------------------------------------------------------------------------

tool(id="url", name="URL / percent encoding", category=CAT,
     summary="%20 and friends — making text safe inside a web address",
     explain=("Anything that would confuse a URL (spaces, &, ?, #, non-English letters) is "
              "replaced by a % followed by its hex byte value. 'Plus for space' is the older "
              "form used by HTML form submissions."),
     example="a b&c  ->  a%20b%26c",
     tags=["percent", "uri", "web"],
     params=[Param("plus", "Use + for space", "bool", False),
             Param("safe", "Characters to leave alone", "text", "", width=12, only="encode")],
     encode=lambda d, plus=False, safe="": (urllib.parse.quote_plus(to_text(d), safe=safe)
                                            if plus else urllib.parse.quote(to_text(d), safe=safe)),
     decode=lambda d, plus=False, **k: (urllib.parse.unquote_plus(to_text(d))
                                        if plus else urllib.parse.unquote(to_text(d))))

tool(id="html", name="HTML entities", category=CAT,
     summary="&amp; &lt; &#169; — text that will not break a web page",
     explain=("Characters with meaning in HTML are written as named or numeric entities so the "
              "browser prints them instead of acting on them. Decoding is the usual reason you "
              "are here: pulling readable text out of scraped HTML."),
     example="<b> & 'x'  ->  &lt;b&gt; &amp; &#x27;x&#x27;",
     tags=["entity", "xml", "web"],
     params=[Param("quotes", "Escape quotes too", "bool", True, only="encode"),
             Param("allnonascii", "Escape every non-ASCII character", "bool", False, only="encode")],
     encode=lambda d, quotes=True, allnonascii=False: _html_enc(to_text(d), quotes, allnonascii),
     decode=lambda d, **k: html.unescape(to_text(d)))


def _html_enc(text, quotes, allnonascii):
    out = html.escape(text, quote=quotes)
    if allnonascii:
        out = "".join(c if ord(c) < 128 else f"&#{ord(c)};" for c in out)
    return out


tool(id="quopri", name="Quoted-printable", category=CAT,
     summary="=3D in email bodies — mostly readable, mostly ASCII",
     explain=("An email encoding that leaves normal text alone and only escapes the awkward "
              "bytes as =XX. If you are reading a raw email and see =20 or =3D everywhere, "
              "this is what you want."),
     tags=["email", "mime", "=3D"],
     encode=lambda d, **k: quopri.encodestring(to_bytes(d)).decode(),
     decode=lambda d, **k: quopri.decodestring(to_bytes(d)),
     binary_ok=True)

tool(id="punycode", name="Punycode / IDNA", category=CAT,
     summary="How non-English domain names are stored (xn--…)",
     explain=("Domain names are ASCII underneath. Punycode maps a Unicode name to an ASCII one "
              "prefixed 'xn--'. Worth knowing for phishing checks — a lookalike domain using "
              "Cyrillic letters shows its true xn-- form here."),
     example="münchen.de  ->  xn--mnchen-3ya.de",
     tags=["idn", "domain", "phishing", "homograph"],
     encode=lambda d, **k: _idna(to_text(d), True),
     decode=lambda d, **k: _idna(to_text(d), False))


def _idna(text, enc):
    parts = []
    for label in text.strip().split("."):
        if not label:
            parts.append(label)
            continue
        try:
            if enc:
                parts.append(label.encode("idna").decode() if not label.isascii()
                             else label)
            else:
                parts.append(label.encode().decode("idna") if label.startswith("xn--")
                             else label)
        except UnicodeError as exc:
            raise ToolError(f"'{label}' is not a valid label ({exc}).") from exc
    return ".".join(parts)


tool(id="uu", name="UUencode", category=CAT,
     summary="The Usenet ancestor of Base64",
     explain=("Older than Base64 and still turns up in Usenet archives and some legacy systems. "
              "Begins with a 'begin 644 filename' line."),
     tags=["usenet", "legacy"],
     params=[Param("filename", "File name in header", "text", "data.bin", only="encode")],
     encode=lambda d, filename="data.bin": _uu_enc(to_bytes(d), filename),
     decode=lambda d, **k: _uu_dec(to_text(d)),
     binary_ok=True)


def _uu_enc(raw, filename):
    """Written out by hand rather than with the `uu` module, which was
    deprecated in Python 3.11 and removed altogether in 3.13. binascii's
    b2a_uu / a2b_uu do the six-bit work and are not going anywhere."""
    import binascii
    name = (filename or "data.bin").strip() or "data.bin"
    lines = [f"begin 644 {name}"]
    for i in range(0, len(raw), 45):
        lines.append(binascii.b2a_uu(raw[i:i + 45]).decode("ascii").rstrip("\n"))
    lines += ["`", "end", ""]
    return "\n".join(lines)


def _uu_dec(text):
    import binascii
    lines = [ln.rstrip("\r") for ln in text.splitlines()]
    start = next((i for i, ln in enumerate(lines)
                  if ln.lower().startswith("begin")), None)
    body = lines[start + 1:] if start is not None else lines
    out = bytearray()
    for line in body:
        stripped = line.strip()
        if stripped.lower() == "end" or stripped == "`":
            break
        if not stripped:
            continue
        try:
            out += binascii.a2b_uu(line)
        except (binascii.Error, ValueError):
            # Mail systems strip trailing spaces; pad the line back out to the
            # length its own leading count character says it should be.
            try:
                n = (ord(line[0]) - 32) & 0x3F
                want = ((n + 2) // 3) * 4 + 1
                out += binascii.a2b_uu(line.ljust(want))[:n]
            except Exception as exc:
                raise ToolError(f"Not valid uuencoded data around: {line[:30]!r}") from exc
    if not out and start is None:
        raise ToolError("That does not look like uuencoded data. It should start with "
                        "a 'begin 644 filename' line.")
    return bytes(out)


# --------------------------------------------------------------------------
# Number bases and character views
# --------------------------------------------------------------------------

tool(id="binary", name="Binary / octal / decimal bytes", category=CAT,
     summary="Every byte written out as a number",
     explain=("Shows the raw numeric value of each byte in whichever base you choose. Binary is "
              "the classic puzzle format; decimal is what you get when someone pastes a "
              "char-code array out of source code."),
     example="Hi  ->  01001000 01101001",
     tags=["bits", "octal", "decimal", "bytes"],
     params=[Param("base", "Base", "choice", "binary", choices=["binary", "octal", "decimal"]),
             Param("sep", "Separator", "text", " ", width=6)],
     encode=lambda d, base="binary", sep=" ": _numbase_enc(to_bytes(d), base, sep),
     decode=lambda d, base="binary", sep=" ": _numbase_dec(to_text(d), base),
     binary_ok=True)


def _numbase_enc(raw, base, sep):
    fmt = {"binary": "{:08b}", "octal": "{:03o}", "decimal": "{:d}"}[base]
    return (sep if sep is not None else " ").join(fmt.format(b) for b in raw)


def _numbase_dec(text, base):
    radix = {"binary": 2, "octal": 8, "decimal": 10}[base]
    body = text.strip()
    toks = [t for t in body.replace(",", " ").split() if t]
    if len(toks) == 1 and base == "binary" and len(toks[0]) % 8 == 0:
        toks = [toks[0][i:i + 8] for i in range(0, len(toks[0]), 8)]
    try:
        vals = [int(t, radix) for t in toks]
    except ValueError as exc:
        raise ToolError(f"Not valid {base} ({exc}).") from exc
    if any(v > 255 or v < 0 for v in vals):
        raise ToolError("Values above 255 are not single bytes.")
    return bytes(vals)


tool(id="unicode-escape", name="Unicode escapes", category=CAT,
     summary=r"é and \x41 — the way code writes awkward characters",
     explain=(r"Converts between real characters and the \uXXXX / \xXX escapes used in "
              "JavaScript, Python, JSON and Java source. Handy when a log or a config file "
              "has escaped everything."),
     tags=["escape", "json", "javascript", r"\u"],
     params=[Param("style", "Style", "choice", r"\uXXXX", choices=[r"\uXXXX", r"\xXX (bytes)", "&#NNN; (numeric)"],
                   only="encode")],
     encode=lambda d, style=r"\uXXXX": _uesc(to_text(d), style),
     decode=lambda d, **k: _udesc(to_text(d)))


def _uesc(text, style):
    if style.startswith(r"\x"):
        return "".join(f"\\x{b:02x}" for b in text.encode("utf-8"))
    if style.startswith("&#"):
        return "".join(f"&#{ord(c)};" if ord(c) > 126 else c for c in text)
    out = []
    for c in text:
        o = ord(c)
        if o < 128:
            out.append(c)
        elif o > 0xFFFF:
            enc = c.encode("utf-16-be")
            out.append("".join(f"\\u{int.from_bytes(enc[i:i+2],'big'):04x}" for i in (0, 2)))
        else:
            out.append(f"\\u{o:04x}")
    return "".join(out)


def _udesc(text):
    try:
        # unicode_escape reads its input as latin-1, so anything beyond that
        # goes in as an escape of its own rather than as mangled UTF-8 bytes
        out = text.encode("latin-1", "backslashreplace").decode("unicode_escape")
        # unicode_escape is latin-1 based; repair UTF-8 that survived it
        try:
            out = out.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
        # \ud83d\ude00 is one character written as a surrogate pair; left as
        # two lone surrogates it cannot be displayed, saved or encoded
        try:
            out = out.encode("utf-16", "surrogatepass").decode("utf-16")
        except UnicodeError:
            pass
        return html.unescape(out)
    except Exception as exc:
        raise ToolError(f"Could not unescape that ({exc}).") from exc


tool(id="unicode-normalise", name="Unicode inspector", category=CAT,
     summary="Name every character — catches invisible and lookalike characters",
     explain=("Lists each character with its code point, official Unicode name and category. "
              "This is how you find the zero-width space, the non-breaking hyphen or the "
              "Cyrillic 'а' that is breaking a search, a password or a domain name."),
     tags=["homoglyph", "invisible", "zero width", "nfc", "nfkd"],
     params=[Param("form", "Also show normalised as", "choice", "NFC",
                   choices=["NFC", "NFD", "NFKC", "NFKD"])],
     action=lambda d, form="NFC": _uinspect(to_text(d), form),
     action_label="Inspect")


def _uinspect(text, form):
    rows = []
    for i, c in enumerate(text):
        try:
            nm = unicodedata.name(c)
        except ValueError:
            nm = "<no name>"
        rows.append((i, repr(c)[1:-1], f"U+{ord(c):04X}", unicodedata.category(c), nm))
    note = ""
    norm = unicodedata.normalize(form, text)
    if norm != text:
        note = f"{form} normalised form differs: {norm!r}"
    suspicious = [r for r in rows if r[3] in ("Cf", "Co", "Cs") or r[2] in ("U+200B", "U+200C", "U+200D", "U+FEFF")]
    return Result(rows=rows, headers=["#", "Char", "Code point", "Cat", "Name"],
                  note=note or f"{len(text)} characters, all unremarkable.",
                  warn=(f"{len(suspicious)} invisible/format character(s) present."
                        if suspicious else ""))


# --------------------------------------------------------------------------
# Human-readable codes
# --------------------------------------------------------------------------

MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
    "'": ".----.", "!": "-.-.--", "/": "-..-.", "(": "-.--.", ")": "-.--.-",
    "&": ".-...", ":": "---...", ";": "-.-.-.", "=": "-...-", "+": ".-.-.",
    "-": "-....-", "_": "..--.-", '"': ".-..-.", "$": "...-..-", "@": ".--.-.",
}
MORSE_REV = {v: k for k, v in MORSE.items()}

tool(id="morse", name="Morse code", category=CAT,
     summary="Dots and dashes, with prosigns and a slash for word breaks",
     explain=("One space between letters, a slash (or three spaces) between words. Decoding "
              "copes with dots written as . or · and dashes as -, – or _."),
     example="SOS  ->  ... --- ...",
     tags=["cw", "radio", "dots", "dashes"],
     params=[Param("word_sep", "Word separator", "text", "/", width=6, only="encode")],
     encode=lambda d, word_sep="/": _morse_enc(to_text(d), word_sep),
     decode=lambda d, **k: _morse_dec(to_text(d)))


def _morse_enc(text, word_sep):
    words = text.upper().split()
    out = []
    for w in words:
        out.append(" ".join(MORSE.get(c, "?") for c in w))
    return f" {word_sep} ".join(out)


def _morse_dec(text):
    s = (text.replace("·", ".").replace("•", ".").replace("–", "-")
             .replace("—", "-").replace("_", "-").strip())
    s = re.sub(r" {3,}", " / ", s)          # three or more spaces is a word break
    for marker in ("/", "|"):
        s = s.replace(marker, " / ")
    words = [w for w in s.split(" / ")]
    out = []
    for w in words:
        letters = [MORSE_REV.get(tok, "?") for tok in w.split() if tok]
        out.append("".join(letters))
    return " ".join(x for x in out if x)


NATO = {"A": "Alfa", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo",
        "F": "Foxtrot", "G": "Golf", "H": "Hotel", "I": "India", "J": "Juliett",
        "K": "Kilo", "L": "Lima", "M": "Mike", "N": "November", "O": "Oscar",
        "P": "Papa", "Q": "Quebec", "R": "Romeo", "S": "Sierra", "T": "Tango",
        "U": "Uniform", "V": "Victor", "W": "Whiskey", "X": "Xray", "Y": "Yankee",
        "Z": "Zulu", "0": "Zero", "1": "One", "2": "Two", "3": "Three",
        "4": "Four", "5": "Five", "6": "Six", "7": "Seven", "8": "Eight", "9": "Nine"}
NATO_REV = {v.upper(): k for k, v in NATO.items()}

tool(id="nato", name="NATO phonetic alphabet", category=CAT,
     summary="Alfa Bravo Charlie — for reading a code down the phone",
     explain="Practical rather than cryptographic: use it to dictate a key, a reference or a password without being misheard.",
     tags=["phonetic", "spelling", "radio"],
     encode=lambda d, **k: " ".join(NATO.get(c.upper(), c) for c in to_text(d) if not c.isspace()),
     decode=lambda d, **k: "".join(NATO_REV.get(w.upper(), "?") for w in to_text(d).split()))

BACON = {c: format(i, "05b").replace("0", "A").replace("1", "B")
         for i, c in enumerate(ALPHA)}
BACON_REV = {v: k for k, v in BACON.items()}

tool(id="bacon", name="Bacon's cipher", category=CAT,
     summary="Each letter as five A/B symbols — the original steganography",
     explain=("Francis Bacon's 1605 code. Each letter becomes five A/B symbols, which can then "
              "be hidden as two typefaces, two colours or upper/lower case in an innocent "
              "sentence. Decoding accepts A/B, 0/1 or upper/lower case."),
     example="HI  ->  AABBB ABAAA",
     tags=["steganography", "baconian", "AB"],
     encode=lambda d, **k: " ".join(BACON[c] for c in to_text(d).upper() if c in ALPHA),
     decode=lambda d, **k: _bacon_dec(to_text(d)))


def _bacon_dec(text):
    s = text.strip()
    if any(c.isalpha() for c in s) and not set(s.upper()) <= set("AB \n\t"):
        bits = "".join("B" if c.isupper() else "A" for c in s if c.isalpha())
    else:
        bits = "".join("A" if c in "Aa0" else "B" for c in s if c in "AaBb01")
    return "".join(BACON_REV.get(bits[i:i + 5], "?") for i in range(0, len(bits) - 4, 5))


TAP = {}
_sq = "ABCDEFGHIJLMNOPQRSTUVWXYZ"   # K folded into C
for _i, _c in enumerate(_sq):
    TAP[_c] = (_i // 5 + 1, _i % 5 + 1)
TAP["K"] = TAP["C"]
TAP_REV = {v: k for k, v in TAP.items() if k != "K"}

tool(id="tap", name="Tap / Polybius knock code", category=CAT,
     summary="Prisoner-of-war knock code — row taps, pause, column taps",
     explain=("A 5×5 grid with K folded into C. Each letter is a row count and a column count. "
              "Written here as dots with a space between the two numbers."),
     example="A  ->  . .    /    H  ->  .. ...",
     tags=["knock", "prison", "polybius"],
     encode=lambda d, **k: "  /  ".join(f"{'.'*r} {'.'*c}" for r, c in
                                        (TAP[ch] for ch in to_text(d).upper() if ch in TAP)),
     decode=lambda d, **k: _tap_dec(to_text(d)))


def _tap_dec(text):
    groups = [g for g in text.replace("/", " ").replace("\n", " ").split("  ") if g.strip()]
    flat = []
    for g in " ".join(groups).split():
        if set(g) <= {".", "·", "*"} and g:
            flat.append(len(g))
        elif g.isdigit():
            flat.extend(int(ch) for ch in g)
    out = ""
    for i in range(0, len(flat) - 1, 2):
        out += TAP_REV.get((flat[i], flat[i + 1]), "?")
    return out


BRAILLE = {
    "a": "⠁", "b": "⠃", "c": "⠉", "d": "⠙", "e": "⠑", "f": "⠋", "g": "⠛",
    "h": "⠓", "i": "⠊", "j": "⠚", "k": "⠅", "l": "⠇", "m": "⠍", "n": "⠝",
    "o": "⠕", "p": "⠏", "q": "⠟", "r": "⠗", "s": "⠎", "t": "⠞", "u": "⠥",
    "v": "⠧", "w": "⠺", "x": "⠭", "y": "⠽", "z": "⠵", " ": " ", ",": "⠂",
    ";": "⠆", ":": "⠒", ".": "⠲", "?": "⠦", "!": "⠖", "'": "⠄", "-": "⠤",
}
BRAILLE_REV = {v: k for k, v in BRAILLE.items()}

tool(id="braille", name="Braille (Grade 1)", category=CAT,
     summary="Uncontracted braille using the Unicode braille block",
     explain=("Letter-for-letter braille. Numbers are prefixed with the number sign ⠼ and "
              "capitals with ⠠, the same as a real braille embosser would."),
     tags=["accessibility", "dots", "unicode"],
     encode=lambda d, **k: _braille_enc(to_text(d)),
     decode=lambda d, **k: _braille_dec(to_text(d)))


def _braille_enc(text):
    out = []
    for c in text:
        if c in "0123456789":
            out.append("⠼" + BRAILLE["abcdefghij"[(int(c) - 1) % 10]])
        elif c.isupper():
            out.append("⠠" + BRAILLE.get(c.lower(), "?"))
        else:
            out.append(BRAILLE.get(c.lower(), c if c.isspace() else "?"))
    return "".join(out)


def _braille_dec(text):
    out, caps, num = [], False, False
    for c in text:
        if c == "⠠":
            caps = True
            continue
        if c == "⠼":
            num = True
            continue
        ch = BRAILLE_REV.get(c, c)
        if num and ch in "abcdefghij":
            ch = str((ord(ch) - 96) % 10)
            num = False
        elif num:
            num = False
        if caps:
            ch, caps = ch.upper(), False
        out.append(ch)
    return "".join(out)


BAUDOT_L = "".join(["\x00", "E", "\n", "A", " ", "S", "I", "U", "\r", "D", "R", "J",
                    "N", "F", "C", "K", "T", "Z", "L", "W", "H", "Y", "P", "Q",
                    "O", "B", "G", "\x0e", "M", "X", "V", "\x0f"])
BAUDOT_F = "".join(["\x00", "3", "\n", "-", " ", "'", "8", "7", "\r", "\x05", "4", "\x07",
                    ",", "!", ":", "(", "5", "+", ")", "2", "#", "6", "0", "1",
                    "9", "?", "&", "\x0e", ".", "/", "=", "\x0f"])

tool(id="baudot", name="Baudot / ITA2 (5-bit teleprinter)", category=CAT,
     summary="The telex code — 5 bits per character with letter/figure shifts",
     explain=("Before ASCII there was ITA2: five bits per character, with two shift codes to "
              "switch between letters and figures. Still turns up in puzzles and in old "
              "telegraphy captures."),
     tags=["ita2", "telex", "teletype", "5-bit"],
     encode=lambda d, **k: _baudot_enc(to_text(d)),
     decode=lambda d, **k: _baudot_dec(to_text(d)))


def _baudot_enc(text):
    out, figs = [], False
    for c in text.upper():
        if c in BAUDOT_L and not (figs and c in BAUDOT_F):
            if figs:
                out.append(format(BAUDOT_L.index("\x0f"), "05b"))
                figs = False
            out.append(format(BAUDOT_L.index(c), "05b"))
        elif c in BAUDOT_F:
            if not figs:
                out.append(format(BAUDOT_L.index("\x0e"), "05b"))
                figs = True
            out.append(format(BAUDOT_F.index(c), "05b"))
        else:
            continue
    return " ".join(out)


def _baudot_dec(text):
    bits = "".join(c for c in text if c in "01")
    out, figs = [], False
    for i in range(0, len(bits) - 4, 5):
        v = int(bits[i:i + 5], 2)
        ch = BAUDOT_F[v] if figs else BAUDOT_L[v]
        if ch == "\x0e":
            figs = True
        elif ch == "\x0f":
            figs = False
        elif ch != "\x00":
            out.append(ch)
    return "".join(out)


LEET = {"a": "4", "b": "8", "e": "3", "g": "6", "i": "1", "l": "1",
        "o": "0", "s": "5", "t": "7", "z": "2"}
LEET_REV = {"4": "a", "8": "b", "3": "e", "6": "g", "1": "i", "0": "o",
            "5": "s", "7": "t", "2": "z", "@": "a", "$": "s", "!": "i"}

tool(id="leet", name="Leetspeak", category=CAT,
     summary="4 for a, 3 for e — password-list substitutions",
     explain=("Not a cipher, but worth having: it is exactly the substitution people make when "
              "a password policy demands a number, and exactly what a cracking wordlist tries "
              "first.\n\nDecoding is a best guess rather than an exact reversal, because the "
              "mapping is lossy - both i and l become 1, so 'hello' comes back as 'heiio'."),
     tags=["1337", "passwords", "substitution"],
     encode=lambda d, **k: "".join(LEET.get(c.lower(), c) for c in to_text(d)),
     decode=lambda d, **k: "".join(LEET_REV.get(c, c) for c in to_text(d)))

tool(id="reverse", name="Reverse / flip text", category=CAT,
     summary="Backwards by character, word or line",
     explain="Trivial but constantly useful when a string 'looks wrong' — and a step in many layered puzzles.",
     tags=["backwards", "mirror"],
     params=[Param("mode", "Reverse by", "choice", "characters",
                   choices=["characters", "words", "lines"])],
     encode=lambda d, mode="characters": _reverse(to_text(d), mode),
     decode=lambda d, mode="characters": _reverse(to_text(d), mode),
     encode_label="Reverse", decode_label="Reverse back")


def _reverse(text, mode):
    if mode == "words":
        return " ".join(reversed(text.split(" ")))
    if mode == "lines":
        return "\n".join(reversed(text.splitlines()))
    return text[::-1]


tool(id="case", name="Change case", category=CAT,
     summary="Upper, lower, title, sentence, snake, kebab, camel",
     explain="Housekeeping rather than cryptography, but it keeps you out of a second app when you are cleaning up decoded output.",
     tags=["upper", "lower", "snake", "camel"],
     params=[Param("style", "Style", "choice", "UPPER",
                   choices=["UPPER", "lower", "Title Case", "Sentence case",
                            "snake_case", "kebab-case", "camelCase", "PascalCase", "aLtErNaTiNg"])],
     action=lambda d, style="UPPER": _case(to_text(d), style),
     action_label="Convert")


def _case(t, style):
    if style == "UPPER":
        return t.upper()
    if style == "lower":
        return t.lower()
    if style == "Title Case":
        return t.title()
    if style == "Sentence case":
        return ". ".join(s.strip().capitalize() for s in t.split(". "))
    words = [w for w in "".join(c if c.isalnum() else " " for c in t).split()]
    if style == "snake_case":
        return "_".join(w.lower() for w in words)
    if style == "kebab-case":
        return "-".join(w.lower() for w in words)
    if style == "camelCase":
        return (words[0].lower() + "".join(w.capitalize() for w in words[1:])) if words else ""
    if style == "PascalCase":
        return "".join(w.capitalize() for w in words)
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(t))


# --------------------------------------------------------------------------
# Number-for-letter, and the rest of the rotations
# --------------------------------------------------------------------------

tool(id="a1z26", name="A1Z26 (letter numbers)", category=CAT,
     summary="A=1, B=2 ... Z=26 - the first substitution anyone invents",
     explain=("Each letter becomes its position in the alphabet. It turns up constantly in "
              "puzzles and escape rooms because it needs no key and no equipment.\n\n"
              "Decoding is tolerant: numbers separated by spaces, dashes, commas or newlines "
              "all work, and a slash or a double space marks a word break."),
     example="ATTACK -> 1-20-20-1-3-11",
     tags=["a1z26", "letter numbers", "alphabet", "puzzle", "numbers"],
     params=[Param("sep", "Separator", "text", "-", width=6),
             Param("word_sep", "Word separator", "text", " / ", width=8, only="encode")],
     encode=lambda d, sep="-", word_sep=" / ": _a1z26_enc(to_text(d), sep, word_sep),
     decode=lambda d, **k: _a1z26_dec(to_text(d)))


def _a1z26_enc(text, sep, word_sep):
    words = []
    for word in text.upper().split():
        words.append((sep or "-").join(str(ord(c) - 64) for c in word if c in ALPHA))
    return (word_sep or " / ").join(w for w in words if w)


def _a1z26_dec(text):
    out = []
    for chunk in re.split(r"\s*[/|]\s*|\s{2,}", text.strip()):
        nums = re.findall(r"\d+", chunk)
        if not nums:
            continue
        out.append("".join(ALPHA[int(n) - 1] if 1 <= int(n) <= 26 else "?" for n in nums))
    return " ".join(out)


tool(id="rot47", name="ROT47", category=CAT,
     summary="ROT13's bigger cousin - rotates punctuation and digits too",
     explain=("Rotates every printable ASCII character (! through ~) by 47 places instead of "
              "rotating only the 26 letters. Because the range is 94 characters wide and 47 is "
              "exactly half of it, applying it twice returns the original - so one button does "
              "both jobs, just like ROT13.\n\n"
              "Worth knowing because ROT13 leaves numbers and punctuation untouched, which "
              "makes it obvious; ROT47 scrambles everything and looks far more like ciphertext "
              "than it deserves to."),
     example="Hello, World! -> w6==@[ (@C=5P",
     security="Not encryption. It has no key at all - anyone can undo it.",
     tags=["rot47", "rot13", "rotate", "ascii", "puzzle"],
     encode=lambda d, **k: _rot47(to_text(d)),
     decode=lambda d, **k: _rot47(to_text(d)),
     encode_label="Apply", decode_label="Apply (same thing)")


def _rot47(text):
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
                   for c in text)


B36 = "0123456789abcdefghijklmnopqrstuvwxyz"
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

tool(id="base62", name="Base62 / Base36", category=CAT,
     summary="Short IDs - the alphabet behind link shorteners",
     explain=("Treats the data as one enormous number and writes it out in base 62 (0-9, A-Z, "
              "a-z) or base 36 (0-9 and one case of letters). That is how short links, video "
              "IDs and many database keys are made compact and URL-safe without any of Base64's "
              "+ / = characters.\n\n"
              "Because it is a pure number conversion, leading zero bytes are not preserved - "
              "the same limitation Base58 has."),
     example="Hi -> 1CxY (base62)",
     tags=["base62", "base36", "short link", "id", "shortener"],
     params=[Param("base", "Base", "choice", "base62", choices=["base62", "base36"])],
     encode=lambda d, base="base62": _bn_enc(to_bytes(d), B62 if base == "base62" else B36),
     decode=lambda d, base="base62": _bn_dec(to_text(d), B62 if base == "base62" else B36),
     binary_ok=True)


def _bn_enc(data, alphabet):
    n = int.from_bytes(data, "big") if data else 0
    if n == 0:
        return alphabet[0] * max(1, len(data))
    out = ""
    base = len(alphabet)
    while n:
        n, r = divmod(n, base)
        out = alphabet[r] + out
    return out


def _bn_dec(text, alphabet):
    s = clean_ws(text)
    base = len(alphabet)
    n = 0
    for ch in s:
        if ch not in alphabet:
            raise ToolError(f"'{ch}' is not a character of this base.")
        n = n * base + alphabet.index(ch)
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


# --------------------------------------------------------------------------
# Compression
# --------------------------------------------------------------------------

COMPRESSORS = ["auto-detect", "gzip", "zlib", "raw deflate", "bzip2", "lzma / xz"]

tool(id="compress", name="Compress / decompress", category=CAT,
     summary="gzip, zlib, deflate, bzip2, xz - and it works out which",
     explain=("Compression is not encryption, but compressed data looks random enough to be "
              "mistaken for it, and a great deal of encoded data turns out to be "
              "Base64-of-gzip once you peel a layer off. Cookies, JWT payloads, API responses "
              "and saved game files do this constantly.\n\n"
              "Decompressing auto-detects the format from its header, so you rarely have to "
              "choose. Raw deflate has no header at all, so it is tried last."),
     example="A JSON blob -> gzip -> Base64 is a very common pairing",
     tags=["gzip", "zlib", "deflate", "bzip2", "xz", "lzma", "zip", "inflate", "compression"],
     params=[Param("algo", "Format", "choice", "auto-detect", choices=COMPRESSORS),
             Param("level", "Compression level", "int", 9, minimum=1, maximum=9, only="encode")],
     encode=lambda d, algo="auto-detect", level=9: _compress(to_bytes(d), algo, int(level)),
     decode=lambda d, algo="auto-detect", **k: _decompress(d, algo),
     encode_label="Compress", decode_label="Decompress",
     binary_ok=True)


def _compress(raw, algo, level):
    from .core import clamp
    level = clamp(level, 1, 9, 9)
    import bz2
    import gzip
    import lzma
    import zlib
    if algo == "auto-detect":
        algo = "gzip"
    if algo == "gzip":
        out = gzip.compress(raw, compresslevel=level)
    elif algo == "zlib":
        out = zlib.compress(raw, level)
    elif algo == "raw deflate":
        c = zlib.compressobj(level, zlib.DEFLATED, -zlib.MAX_WBITS)
        out = c.compress(raw) + c.flush()
    elif algo == "bzip2":
        out = bz2.compress(raw, compresslevel=level)
    else:
        out = lzma.compress(raw, preset=level)
    saved = (1 - len(out) / len(raw)) * 100 if raw else 0
    return Result(text=base64.b64encode(out).decode(), data=out,
                  suggested_name="compressed.bin",
                  note=f"{algo}: {len(raw):,} bytes -> {len(out):,} "
                       f"({saved:+.0f}%). Shown as Base64; Save keeps the raw bytes.")


def sniff_compression(raw: bytes):
    """Which compression format, by header. None if nothing recognisable."""
    if raw[:2] == b"\x1f\x8b":
        return "gzip"
    if raw[:3] == b"BZh" and raw[3:4].isdigit():
        return "bzip2"
    if raw[:6] == b"\xfd7zXZ\x00":
        return "lzma / xz"
    if raw[:1] == b"\x5d" and raw[1:3] == b"\x00\x00":
        return "lzma / xz"
    if len(raw) > 2 and raw[0] & 0x0F == 8 and ((raw[0] << 8) + raw[1]) % 31 == 0:
        return "zlib"
    return None


def decompress_bytes(raw: bytes, algo="auto-detect"):
    """Returns (decompressed bytes, the format that worked)."""
    import bz2
    import gzip
    import lzma
    import zlib
    order = [algo] if algo != "auto-detect" else []
    if not order:
        guess = sniff_compression(raw)
        order = ([guess] if guess else []) + ["gzip", "zlib", "bzip2", "lzma / xz", "raw deflate"]
    seen = []
    for name in order:
        if name in seen:
            continue
        seen.append(name)
        try:
            if name == "gzip":
                return gzip.decompress(raw), name
            if name == "zlib":
                return zlib.decompress(raw), name
            if name == "raw deflate":
                return zlib.decompress(raw, -zlib.MAX_WBITS), name
            if name == "bzip2":
                return bz2.decompress(raw), name
            if name == "lzma / xz":
                return lzma.decompress(raw), name
        except Exception:
            continue
    return None, None


def _decompress(data, algo):
    raw = to_bytes(data)
    if not raw.strip():
        raise ToolError("Nothing to decompress.")
    # A compressed blob is nearly always handed over as Base64 or hex
    if all(32 <= b < 127 or b in (9, 10, 13) for b in raw):
        from .core import decode_as, sniff_format
        guess = sniff_format(to_text(data))
        # sniff_format will not commit on anything short, but a few compressed
        # bytes are only a dozen Base64 characters - so try both regardless
        for guess in ([guess] if guess in ("hex", "base64") else ["base64", "hex"]):
            try:
                candidate = decode_as(data, guess)[0]
            except ToolError:
                continue
            out, used = decompress_bytes(candidate, algo)
            if out is not None:
                return _decompressed_result(out, used, f"{guess} then ")
    out, used = decompress_bytes(raw, algo)
    if out is None:
        raise ToolError("That is not compressed data Cryptex recognises "
                        "(gzip, zlib, raw deflate, bzip2 or xz). If it is Base64 or hex of "
                        "compressed data, decode that layer first - or use Auto-solve, "
                        "which peels layers for you.")
    return _decompressed_result(out, used, "")


def _decompressed_result(out, used, prefix):
    try:
        text = out.decode("utf-8")
        return Result(text=text, data=out,
                      note=f"{prefix}{used}: expanded to {len(out):,} bytes.")
    except UnicodeDecodeError:
        return Result(text=pretty_hex(out), data=out,
                      note=f"{prefix}{used}: expanded to {len(out):,} bytes of binary data.")


# --------------------------------------------------------------------------
# More encodings: Base45, Z85, Base91, XXencode
# --------------------------------------------------------------------------

_B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def _base45_enc(data: bytes) -> str:
    out = []
    for i in range(0, len(data), 2):
        chunk = data[i:i + 2]
        if len(chunk) == 2:
            n = chunk[0] * 256 + chunk[1]
            c, n = n % 45, n // 45
            d, e = n % 45, n // 45
            out += [_B45[c], _B45[d], _B45[e]]
        else:
            n = chunk[0]
            out += [_B45[n % 45], _B45[n // 45]]
    return "".join(out)


def _base45_dec(text: str) -> bytes:
    text = "".join(ch for ch in text if ch not in "\r\n\t")  # space is a Base45 char
    vals = []
    for ch in text:
        if ch not in _B45:
            raise ToolError(f"'{ch}' is not a Base45 character.")
        vals.append(_B45.index(ch))
    out = bytearray()
    for i in range(0, len(vals), 3):
        group = vals[i:i + 3]
        if len(group) == 3:
            n = group[0] + group[1] * 45 + group[2] * 45 * 45
            if n > 0xFFFF:
                raise ToolError("Not valid Base45 (a group is out of range).")
            out += bytes([n // 256, n % 256])
        elif len(group) == 2:
            n = group[0] + group[1] * 45
            if n > 0xFF:
                raise ToolError("Not valid Base45 (a trailing group is out of range).")
            out.append(n)
        else:
            raise ToolError("Not valid Base45 - the length is wrong (groups are 2 or 3).")
    return bytes(out)


tool(id="base45", name="Base45", category=CAT,
     summary="The compact alphabet behind QR codes and EU digital certificates",
     explain=(
         "Base45 packs bytes into a 45-character alphabet chosen to be efficient inside a QR "
         "code's alphanumeric mode. It is what the EU Digital COVID Certificate used, and it "
         "turns up wherever data is going into a QR that should stay small.\n\n"
         "Every two bytes become three Base45 characters. It is denser in a QR than Base64 "
         "even though the alphabet is smaller, because QR codes encode that character set "
         "specially."),
     tags=["base45", "qr", "covid certificate", "rfc 9285", "encoding"],
     encode=lambda d, **k: _base45_enc(to_bytes(d)),
     decode=lambda d, **k: _base45_dec(to_text(d)), binary_ok=True)


_Z85 = ("0123456789abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")


def _z85_enc(data: bytes) -> str:
    if len(data) % 4:
        raise ToolError("Z85 needs a length that is a multiple of 4 bytes. Pad it, or use "
                        "Base85, which does not.")
    out = []
    for i in range(0, len(data), 4):
        n = int.from_bytes(data[i:i + 4], "big")
        chars = []
        for _ in range(5):
            chars.append(_Z85[n % 85]); n //= 85
        out += reversed(chars)
    return "".join(out)


def _z85_dec(text: str) -> bytes:
    text = "".join(text.split())
    if len(text) % 5:
        raise ToolError("Z85 text length must be a multiple of 5.")
    out = bytearray()
    for i in range(0, len(text), 5):
        n = 0
        for ch in text[i:i + 5]:
            if ch not in _Z85:
                raise ToolError(f"'{ch}' is not a Z85 character.")
            n = n * 85 + _Z85.index(ch)
        out += n.to_bytes(4, "big")
    return bytes(out)


tool(id="z85", name="Z85 (ZeroMQ Base85)", category=CAT,
     summary="ZeroMQ's Base85 - the variant safe to paste into source code",
     explain=(
         "Z85 is the flavour of Base85 defined by ZeroMQ. Its alphabet deliberately avoids "
         "the quotes, backslashes and backticks that make other Base85 variants a pain to "
         "embed in source code or config files, so it is the one to use when the result has "
         "to live inside a string literal.\n\n"
         "It works in 4-byte groups, so the input length must be a multiple of four. For "
         "arbitrary data use the main Base85 tool instead."),
     tags=["z85", "base85", "zeromq", "ascii85", "encoding"],
     encode=lambda d, **k: _z85_enc(to_bytes(d)),
     decode=lambda d, **k: _z85_dec(to_text(d)), binary_ok=True)


_B91 = ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        '!#$%&()*+,./:;<=>?@[]^_`{|}~"')


def _base91_enc(data: bytes) -> str:
    b, n, out = 0, 0, []
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13; n -= 13
            else:
                v = b & 16383; b >>= 14; n -= 14
            out += [_B91[v % 91], _B91[v // 91]]
    if n:
        out.append(_B91[b % 91])
        if n > 7 or b > 90:
            out.append(_B91[b // 91])
    return "".join(out)


def _base91_dec(text: str) -> bytes:
    text = "".join(text.split())
    idx = {c: i for i, c in enumerate(_B91)}
    v = -1
    b = n = 0
    out = bytearray()
    for ch in text:
        if ch not in idx:
            raise ToolError(f"'{ch}' is not a basE91 character.")
        c = idx[ch]
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                out.append(b & 255); b >>= 8; n -= 8
            v = -1
    if v + 1:
        out.append((b | v << n) & 255)
    return bytes(out)


tool(id="base91", name="basE91", category=CAT,
     summary="Denser than Base64 - squeezes more data into printable ASCII",
     explain=(
         "basE91 fits arbitrary binary into printable ASCII more tightly than Base64: about "
         "23% overhead against Base64's 33%, because it uses almost the whole printable range "
         "and a variable number of bits per character.\n\n"
         "The trade-off is that the output is not a fixed block size and includes most "
         "punctuation, so it is less friendly to paste into places with their own escaping. "
         "Reach for it when size matters more than tidiness."),
     tags=["base91", "base64", "dense", "encoding", "ascii"],
     encode=lambda d, **k: _base91_enc(to_bytes(d)),
     decode=lambda d, **k: _base91_dec(to_text(d)), binary_ok=True)


def _xxencode(data: bytes) -> str:
    tbl = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    lines = []
    for i in range(0, len(data), 45):
        chunk = data[i:i + 45]
        line = [tbl[len(chunk)]]
        pad = chunk + b"\x00" * ((-len(chunk)) % 3)
        for j in range(0, len(pad), 3):
            n = (pad[j] << 16) | (pad[j + 1] << 8) | pad[j + 2]
            line += [tbl[(n >> 18) & 63], tbl[(n >> 12) & 63],
                     tbl[(n >> 6) & 63], tbl[n & 63]]
        lines.append("".join(line))
    return "\n".join(lines)


def _xxdecode(text: str) -> bytes:
    tbl = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    idx = {c: i for i, c in enumerate(tbl)}
    out = bytearray()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("begin", "end")):
            continue
        if line[0] not in idx:
            continue
        count = idx[line[0]]
        body = line[1:]
        raw = bytearray()
        for j in range(0, len(body), 4):
            grp = body[j:j + 4]
            if len(grp) < 4:
                break
            n = 0
            for ch in grp:
                n = (n << 6) | idx.get(ch, 0)
            raw += bytes([(n >> 16) & 255, (n >> 8) & 255, n & 255])
        out += raw[:count]
    return bytes(out)


tool(id="xxencode", name="XXencode", category=CAT,
     summary="The uuencode cousin that survives systems uuencode couldn't",
     explain=(
         "XXencode does the same job as uuencode - wrap binary as text for old mail and Usenet "
         "- but with an alphabet of only letters, digits, plus and minus. That was the point: "
         "uuencode's punctuation got mangled by some mainframe character sets and EBCDIC "
         "gateways, and XXencode's tamer alphabet came through intact.\n\n"
         "You still meet it in old archives and the occasional puzzle. Each line starts with a "
         "length character, then groups of four encode three bytes each."),
     tags=["xxencode", "uuencode", "usenet", "binary", "encoding"],
     encode=lambda d, **k: _xxencode(to_bytes(d)),
     decode=lambda d, **k: _xxdecode(to_text(d)), binary_ok=True)
