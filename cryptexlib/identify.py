"""Identify — paste anything and get a ranked list of what it probably is.

This is the tool to open first. It does not decode anything; it tells you which
of the other tools to point at the problem.
"""
from __future__ import annotations

import base64
import binascii
import re

from .analysis import _identify_magic
from .classical import byte_english_score, index_of_coincidence
from .language import readability
from .core import ALPHA, Result, ToolError, clean_ws, strip_non_alpha, to_text, tool

CAT = "Identify"


def _pct(s, pred):
    return (sum(1 for c in s if pred(c)) / len(s)) if s else 0.0


PLAIN_ENGLISH = {w.upper() for w in """the be to of and a in that have i it for not on with he as you do at
this but his by from they we say her she or an will my one all would there their what so up out if
about who get which go me when make can like time no just him know take people into year your good
some could them see other than then now look only come its over think also back after use two how
our work first well way even new want because any these give day most us is was are been has had
were said did got went thing man men woman women name water long little very much before here
through great where should never each between own under last right old while might again off down
next few own place while""".split()}

CHECKS = []


def check(fn):
    CHECKS.append(fn)
    return fn


@check
def _c_empty(s, body):
    if not s.strip():
        return [("Nothing", 100, "There is no input to identify.", "")]
    return []


@check
def _c_hash(s, body):
    out = []
    if re.fullmatch(r"[0-9a-fA-F]+", body) and len(body) in (32, 40, 56, 64, 96, 128):
        names = {32: "MD5 or NTLM", 40: "SHA-1 or RIPEMD-160", 56: "SHA-224",
                 64: "SHA-256, SHA3-256 or BLAKE2s", 96: "SHA-384", 128: "SHA-512 or SHA3-512"}
        out.append((f"Hash digest — {names[len(body)]}", 92,
                    f"{len(body)} hex characters = {len(body)//2} bytes, exactly a digest length.",
                    "Hashes are one-way. Cryptex cannot reverse it — use 'Hash text' to test candidate inputs, "
                    "or an online lookup for common passwords."))
    for prefix, name in (("$2a$", "bcrypt"), ("$2b$", "bcrypt"), ("$2y$", "bcrypt"),
                         ("$argon2", "Argon2"), ("$6$", "SHA-512 crypt"), ("$5$", "SHA-256 crypt"),
                         ("$1$", "MD5 crypt"), ("$pbkdf2", "PBKDF2")):
        if s.startswith(prefix):
            out.append((f"Password hash — {name}", 97, f"Starts with the {name} marker '{prefix}'.",
                        "Deliberately slow and one-way. Not reversible."))
    return out


@check
def _c_jwt(s, body):
    parts = s.strip().split(".")
    if len(parts) == 3 and parts[0].startswith("ey"):
        return [("JSON Web Token (JWT)", 96,
                 "Three dot-separated Base64url parts beginning 'ey' (which is '{\"' in Base64).",
                 "Decode each part with Base64 (URL-safe). The third part is a signature — "
                 "it proves the token was not altered, it does not hide anything.")]
    return []


@check
def _c_pem(s, body):
    if "-----BEGIN" in s:
        m = re.search(r"-----BEGIN ([A-Z0-9 ]+)-----", s)
        what = m.group(1).title() if m else "PEM block"
        return [(f"PEM — {what}", 98, "PEM armour is unmistakable.",
                 "Use 'Inspect key or certificate' to read it.")]
    if s.startswith(("ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-")):
        return [("OpenSSH public key", 97, "Starts with an OpenSSH key type name.",
                 "Use 'Inspect key or certificate' for its fingerprint.")]
    return []


@check
def _c_base(s, body):
    out = []
    wordy = (" " in s.strip()
             and all(w.isalpha() for w in s.split())
             and not s.strip().isupper())
    if len(body) >= 12 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", s) and not s.isdigit():
        pad_ok = len(body.rstrip("=")) % 4 != 1
        try:
            dec = base64.b64decode(body + "=" * (-len(body) % 4), validate=False)
        except binascii.Error:
            dec = b""
        conf = 50 + (15 if body.endswith("=") else 0) + (10 if pad_ok else -30)
        why = "Only Base64 characters."
        extra = ""
        magic = _identify_magic(dec)
        printable = (sum(1 for b in dec if 32 <= b < 127 or b in (9, 10, 13)) / len(dec)) if dec else 0
        if magic:
            conf += 35
            extra = f"Decoded bytes look like: {magic}."
        elif dec and printable > 0.95 and byte_english_score(dec) > -4.2:
            conf += 35
            extra = f"Decodes to readable text: {dec[:60].decode('latin-1')!r}"
        elif dec and printable > 0.9:
            conf += 15
            extra = f"Decodes to printable text: {dec[:40].decode('latin-1')!r}"
        if any(c.isdigit() for c in body) and any(c.islower() for c in body) and any(c.isupper() for c in body):
            conf += 8   # mixed case + digits is the Base64 look, not the English look
        if wordy:
            conf -= 30  # spaced, all-alphabetic words are a sentence, not Base64
        out.append(("Base64", min(conf, 97), why + " " + extra,
                    "Use the Base64 tool. If it decodes to more Base64, keep going — layering is common."))
    if len(body) >= 8 and re.fullmatch(r"[A-Za-z0-9\-_=\s]+", s) and ("-" in body or "_" in body):
        out.append(("Base64 (URL-safe)", 70, "Uses - and _ in place of + and /.",
                    "Tick 'URL-safe alphabet' in the Base64 tool."))
    if len(body) >= 8 and re.fullmatch(r"[A-Z2-7=\s]+", s.upper()) and not re.fullmatch(r"[0-9\s]+", s):
        digits = any(c in "234567" for c in body)
        out.append(("Base32", 62 if digits else 35,
                    "Only A–Z and 2–7 — the Base32 alphabet."
                    + ("" if digits else " No digits present, so this may simply be upper-case text."),
                    "Common for authenticator (TOTP) secrets."))
    if re.fullmatch(r"(0x)?[0-9a-fA-F\s:,]+", s) and len(re.sub(r"[^0-9a-fA-F]", "", s)) % 2 == 0:
        hx = re.sub(r"[^0-9a-fA-F]", "", s)
        if len(hx) >= 6:
            dec = bytes.fromhex(hx)
            magic = _identify_magic(dec)
            printable = (sum(1 for b in dec if 32 <= b < 127) / len(dec)) if dec else 0
            conf = 72 + (20 if magic else 0)
            readable = ""
            if printable > 0.95 and byte_english_score(dec) > -4.2:
                conf += 15
                readable = f" Decodes to readable text: {dec[:40].decode('latin-1')!r}"
            out.append(("Hex (Base16)", min(conf, 96),
                        "Only hex digits, an even number of them."
                        + (f" Decodes to: {magic}." if magic else "") + readable,
                        "Use the Base16 / Hex tool."))
    if re.fullmatch(r"[01\s]+", s) and len(re.sub(r"\s", "", s)) >= 16:
        bits = re.sub(r"\s", "", s)
        out.append(("Binary", 88 if len(bits) % 8 == 0 else 60,
                    f"{len(bits)} bits" + (", a whole number of bytes." if len(bits) % 8 == 0
                                           else " — not a multiple of 8, so check the grouping."),
                    "Use 'Binary / octal / decimal bytes'."))
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", s.strip()) and 20 <= len(s.strip()) <= 64:
        out.append(("Base58", 45, "No 0, O, I or l — the Base58 alphabet. Bitcoin addresses look like this.",
                    "Use the Base58 tool."))
    return out


@check
def _c_web(s, body):
    out = []
    if re.search(r"%[0-9a-fA-F]{2}", s):
        out.append(("URL / percent encoded", 85, "Contains %XX sequences.", "Use the URL tool."))
    if re.search(r"&(#\d+|#x[0-9a-fA-F]+|[a-z]{2,10});", s):
        out.append(("HTML entities", 85, "Contains &name; or &#number; sequences.", "Use the HTML entities tool."))
    if re.search(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", s):
        out.append(("Unicode / hex escapes", 82, r"Contains \uXXXX or \xXX sequences.",
                    "Use the Unicode escapes tool."))
    if re.search(r"=[0-9A-F]{2}", s) and s.count("=") > 2:
        out.append(("Quoted-printable", 55, "Repeated =XX sequences, typical of raw email bodies.",
                    "Use the Quoted-printable tool."))
    if s.strip().startswith("xn--") or ".xn--" in s:
        out.append(("Punycode domain", 90, "Contains an 'xn--' label.",
                    "Decode it — lookalike domains hide here."))
    return out


@check
def _c_morse(s, body):
    core = re.sub(r"[\s/|]", "", s.replace("·", ".").replace("–", "-").replace("_", "-"))
    if core and set(core) <= {".", "-"} and len(core) >= 4:
        return [("Morse code", 95, "Nothing but dots, dashes and separators.", "Use the Morse code tool.")]
    return []


@check
def _c_classical(s, body):
    letters = strip_non_alpha(s).upper()
    if len(letters) < 12 or len(letters) / max(len(s), 1) < 0.5:
        return []
    out = []
    # Mixed case plus digits plus no spaces is the shape of an encoding, not of
    # a classical cipher, which is written in one case and usually in groups.
    encodingish = (any(c.isdigit() for c in s) and any(c.islower() for c in s)
                   and any(c.isupper() for c in s) and " " not in s.strip())
    drop = 35 if encodingish else 0
    ioc = index_of_coincidence(letters)
    distinct = len(set(letters))
    if set(letters) <= set("ADFGVX") and distinct >= 4:
        out.append(("ADFGVX / ADFGX cipher", 93, "Only the letters A D F G V X appear.",
                    "Use the ADFGX / ADFGVX tool. You need both keywords."))
    if set(letters) <= set("AB") and len(letters) % 5 == 0:
        out.append(("Bacon's cipher", 88, "Only A and B, in a multiple of five.", "Use the Bacon tool."))
    if ioc > 0.060:
        words = {w.strip(".,!?;:'\"()").upper() for w in s.split()}
        readable = len(words & PLAIN_ENGLISH) >= 2
        if readable:
            out.append(("Plain English text", 82,
                        "It is already readable - ordinary English words and English letter "
                        "frequencies. Nothing has been done to it.",
                        "If you expected this to be encoded, check you pasted the right thing."))
        else:
            out.append(("Substitution cipher (or plain English)", 70 - drop,
                        f"Index of coincidence {ioc:.4f} - English-shaped letter frequencies.",
                        "Try Caesar brute force first, then Frequency analysis and Simple "
                        "substitution. If the letters are all still there but scrambled, it "
                        "is a transposition."))
    elif 0.038 <= ioc <= 0.050 and distinct > 20:
        out.append(("Polyalphabetic cipher (Vigenère family)", 68 - drop,
                    f"Index of coincidence {ioc:.4f} — too flat for a substitution cipher.",
                    "Run Kasiski examination, then the Vigenère solver."))
    if re.fullmatch(r"[1-5\s]+", s.strip()) and len(re.sub(r"\s", "", s)) % 2 == 0:
        out.append(("Polybius square / tap code", 80, "Only the digits 1–5, in pairs.",
                    "Use the Polybius square or Tap code tool."))
    return out


@check
def _c_new_formats(s, body):
    """A1Z26, ROT47, Base62 and compressed data."""
    out = []
    nums = re.findall(r"\d+", s)
    if (len(nums) >= 3 and re.fullmatch(r"[\d\s,;/|.\-]+", s.strip())
            and all(1 <= int(n) <= 26 for n in nums)):
        from .encodings import _a1z26_dec
        try:
            plain = _a1z26_dec(s)
        except Exception:
            plain = ""
        conf = 74 + (18 if plain and readability(plain) > 0.4 else 0)
        out.append(("A1Z26 (letter numbers)", conf,
                    f"{len(nums)} numbers, all between 1 and 26."
                    + (f" Reads as: {plain[:40]!r}" if plain else ""),
                    "Use the A1Z26 tool, or Auto-solve."))
    if len(body) >= 10 and sum(1 for c in s if 33 <= ord(c) <= 126) / max(1, len(s)) > 0.8:
        from .encodings import _rot47
        turned = _rot47(s)
        if readability(turned) > 0.45:
            out.append(("ROT47", 90,
                        f"Rotating it 47 places gives readable text: {turned[:44]!r}",
                        "Use the ROT47 tool."))
    for name, raw in _decoded_views(s):
        from .encodings import sniff_compression
        kind = sniff_compression(raw)
        if kind:
            out.append((f"{name} of {kind}-compressed data", 98,
                        f"Decoding the {name} gives a {kind} header.",
                        "Auto-solve will peel both layers in one go."))
        magic = _identify_magic(raw)
        if magic and not kind:
            out.append((f"{name} of {magic}", 96,
                        f"Decoding the {name} gives {magic}.",
                        "Decode it, then Save the result to a file."))
    return out


@check
def _c_hidden_and_tokens(s, body):
    """Zero-width text, otpauth URIs, Shamir pieces, checksum manifests,
    Enigma-shaped ciphertext and AX.25 payloads."""
    out = []

    invisible = sum(1 for c in s if c in "\u200b\u200c\u200d\u2060\ufeff")
    if invisible >= 8:
        bits = sum(1 for c in s if c in "\u200b\u200c")
        out.append(("Text with something hidden in it", 96,
                    f"{invisible} zero-width characters are in here, printing as "
                    f"nothing - about {bits // 8} bytes' worth.",
                    "Use 'Hide text inside text' and press Reveal."))

    low = s.strip().lower()
    if "-----BEGIN AGE ENCRYPTED FILE-----" in s or s.strip().startswith("age-encryption.org"):
        out.append(("age encrypted file", 99,
                    "The age-encryption.org header - a file encrypted with age.",
                    "Use the age tool with your secret identity or the passphrase."))
    if "hxxp" in low or "[.]" in s or "[at]" in low or "(dot)" in low:
        out.append(("Defanged indicator", 90,
                    "A defanged URL, IP or email (hxxp, [.], [at]) - made safe to share.",
                    "Refang it with the defang tool to get the real indicator back."))
    if "Received:" in s and ("From:" in s or "from " in s):
        out.append(("Email headers", 88,
                    "Raw email headers with a Received chain.",
                    "Run the email-header analyser to trace the delivery path."))
    if s.strip().startswith("AGE-SECRET-KEY-1"):
        out.append(("age secret identity", 99, "An age private key.",
                    "Paste it into the age tool to decrypt."))
    if s.strip().startswith("age1") and 50 <= len(s.strip()) <= 70 and " " not in s.strip():
        out.append(("age recipient key", 92, "An age public key.",
                    "Encrypt to it with the age tool."))
    if low.startswith("otpauth://"):
        out.append(("Authenticator set-up URI", 99,
                    "This is what a two-factor set-up QR code contains.",
                    "Use 'Authenticator codes' to get the current code."))

    lines = [ln.strip() for ln in s.strip().splitlines() if ln.strip()]
    if lines and all(re.fullmatch(r"\d+-\d+-[A-Z2-7=]{20,}", ln) for ln in lines):
        need = lines[0].split("-")[0]
        out.append(("Shamir secret share", 97,
                    f"{len(lines)} piece(s) of a split secret; {need} are needed "
                    "to rebuild it.",
                    "Paste them all into 'Split a secret' and press Rebuild."))

    if len(lines) >= 2 and all(
            re.fullmatch(r"[0-9a-fA-F]{32,128}\s+\*?\S.*", ln) for ln in lines[:8]):
        out.append(("Checksum manifest", 92,
                    f"{len(lines)} lines of 'hash  filename' - the SHA256SUMS format.",
                    "Use 'Check a checksum manifest'."))

    if re.fullmatch(r"[A-Za-z0-9+/=_\-]+\.[A-Za-z0-9+/=_\-]+\.[A-Za-z0-9+/=_\-]*",
                    s.strip()) and s.count(".") == 2:
        out.append(("JSON Web Token", 97,
                    "Three base64url pieces separated by dots.",
                    "Use the JWT tool - it will decode the claims and check "
                    "the signature."))

    letters = [c for c in s.upper() if c.isalpha() and c.isascii()]
    if len(letters) >= 60 and len(letters) == len([c for c in s if not c.isspace()]):
        groups = s.split()
        if groups and len(groups) > 4 and all(len(g) == 5 for g in groups[:-1]):
            out.append(("Machine-cipher ciphertext (five-letter groups)",
                        72 if len(groups) >= 10 else 62,
                        "All letters, no digits or punctuation, sent in groups of "
                        "five - the shape of Enigma and other machine traffic.",
                        "Try the Enigma solver, or Auto-solve."))

    if re.match(r"^[A-Z0-9]{1,6}(-\d{1,2})?>[A-Z0-9]{1,6}", s.strip()):
        out.append(("APRS / AX.25 packet", 88,
                    "A callsign, a '>' and a destination - the way packet frames "
                    "are written down.",
                    "The packet decoder reads these off the air."))
    return out


def _decoded_views(s):
    """What this turns into under the obvious decoders - so detection can see
    one layer deeper than the surface."""
    import base64 as _b64
    body = clean_ws(s)
    views = []
    if len(body) >= 12 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", body):
        try:
            views.append(("Base64", _b64.b64decode(
                body.replace("-", "+").replace("_", "/") + "=" * (-len(body) % 4))))
        except Exception:
            pass
    if len(body) >= 12 and len(body) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", body):
        try:
            views.append(("hex", bytes.fromhex(body)))
        except Exception:
            pass
    return views


@check
def _c_structured(s, body):
    out = []
    t = s.strip()
    if (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]")):
        out.append(("JSON", 80, "Balanced braces or brackets.", "Not encoded at all — just data."))
    if t.startswith("<") and t.endswith(">") and "</" in t:
        out.append(("XML or HTML", 80, "Tag structure.", "Not encoded — you may want HTML entity decoding."))
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", t):
        out.append(("UUID / GUID", 96, "Standard 8-4-4-4-12 shape.", "An identifier, not a secret."))
    if re.fullmatch(r"\d{9,13}", t):
        out.append(("Unix timestamp", 50, "9–13 digits.",
                    f"{t[:10]} seconds is roughly " +
                    __import__("datetime").datetime.fromtimestamp(int(t[:10]), __import__("datetime").timezone.utc).strftime("%d %b %Y") + " UTC."))
    return out


def _identify(text):
    s = to_text(text)
    body = clean_ws(s)
    hits = []
    for fn in CHECKS:
        try:
            hits.extend(fn(s, body))
        except Exception:
            continue
    if not hits:
        hits = [("Unrecognised", 0,
                 "Nothing matched a known shape.",
                 "Try Frequency analysis and Entropy — high entropy with no structure usually means "
                 "genuinely encrypted data rather than encoded data.")]
    hits.sort(key=lambda h: -h[1])
    rows = [(name, f"{conf}%", why, advice) for name, conf, why, advice in hits]
    lines = []
    for name, conf, why, advice in hits:
        lines.append(f"{conf:>3}%  {name}\n      {why}" + (f"\n      -> {advice}" if advice else ""))
    return Result(text="\n\n".join(lines), rows=rows,
                  headers=["Best guess", "Confidence", "Why", "What to do"],
                  note=f"{len(s)} characters examined, {len(hits)} candidate(s).")


tool(id="identify", name="What is this?", category=CAT,
     summary="Paste anything — get a ranked guess and which tool to use next",
     explain=("Start here when you have a blob of something and no idea what it is. Cryptex "
              "checks it against every shape it knows — encodings, hash lengths, key formats, "
              "cipher fingerprints, file magic bytes — and ranks the possibilities with a "
              "reason for each and the tool that will take it further.\n\n"
              "It never changes your input, so it is always safe to run first."),
     tags=["detect", "what is this", "unknown", "triage"],
     action=_identify, action_label="Identify")


# --------------------------------------------------------------------------
# Which tool does each guess point at?
# --------------------------------------------------------------------------

SUGGEST = [
    ("Base64 (URL-safe)", "base64"), ("Base64", "base64"), ("Base32", "base32"),
    ("Base58", "base58"), ("Hex (Base16)", "base16"), ("Binary", "binary"),
    ("Morse code", "morse"), ("URL / percent", "url"), ("HTML entities", "html"),
    ("Unicode / hex escapes", "unicode-escape"), ("Quoted-printable", "quopri"),
    ("Punycode domain", "punycode"), ("JSON Web Token", "jwt"),
    ("PEM", "inspect-key"), ("OpenSSH public key", "inspect-key"),
    ("Hash digest", "hash-text"), ("Password hash", "password-hash"),
    ("ADFGVX", "adfgvx"), ("Bacon's cipher", "bacon"),
    ("Substitution cipher", "caesar-brute"),
    ("Polyalphabetic cipher", "vigenere-solve"),
    ("Polybius square", "polybius"),
    ("A1Z26", "a1z26"),
    ("ROT47", "rot47"),
    ("Base62", "base62"),
    ("Text with something hidden in it", "zero-width"),
    ("age encrypted file", "age"), ("age secret identity", "age"),
    ("age recipient key", "age"),
    ("Defanged indicator", "defang"), ("Email headers", "email-headers"),
    ("Authenticator set-up URI", "totp"),
    ("Shamir secret share", "shamir"),
    ("Checksum manifest", "manifest-check"),
    ("Machine-cipher ciphertext", "enigma-crack"),
    ("APRS / AX.25 packet", "aprs"),
    ("Plain English text", None),
]

# Anything whose name says another layer is underneath goes straight to the
# solver rather than to a single-step tool.
_TO_SOLVER = ("of gzip", "of zlib", "of bzip2", "of lzma", "-compressed",
              "of PNG", "of JPEG", "of ZIP", "of PDF", "of GIF")


def suggest_tool(name: str):
    if any(marker in name for marker in _TO_SOLVER):
        return "auto-solve"
    for prefix, tool_id in SUGGEST:
        if name.startswith(prefix):
            return tool_id
    return None


def quick_identify(text: str):
    """The single best guess, for the live hint under the input box.

    Returns (name, confidence, advice, tool id) or None when nothing is
    confident enough to be worth interrupting for.
    """
    if not text or not text.strip() or len(text) > 200_000:
        return None
    body = clean_ws(text)
    hits = []
    for fn in CHECKS:
        try:
            hits.extend(fn(text, body))
        except Exception:
            continue
    hits = [h for h in hits
            if h[1] >= 70 and h[0] not in ("Nothing", "Unrecognised", "Plain English text")]
    if not hits:
        return None
    hits.sort(key=lambda h: -h[1])
    name, conf, _why, advice = hits[0]
    return name, conf, advice, suggest_tool(name)
