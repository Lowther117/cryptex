"""Auto-solve: work out what was done to something, and undo it.

The detector says what one layer looks like. This searches: it tries every
transform that could plausibly apply, scores what comes out, and recurses -
because real puzzles are layered, and Base64 wrapped round gzip wrapped round
a Caesar shift is an ordinary Tuesday.

Two kinds of transform are tried.

*Decoders* are deterministic - Base64, hex, Morse, gzip. Each is gated by a
cheap shape test, so they only run where they could possibly succeed.

*Brute-force families* have a key space small enough to sweep - all 25 Caesar
shifts, all 312 affine keys, rail fences up to twelve rails, all 256 single-byte
XORs - plus the statistical solvers for Vigenere and repeating-key XOR. These
sweep their whole space, score every result, and hand back only the best one or
two, so the search tree stays a tree rather than an explosion.

Everything is ranked by `language.readability`, which is deliberately hard to
fool: recognisable structure or actual English words score high, letters that
merely have English-ish frequencies score middling, noise scores near zero.
"""
from __future__ import annotations

import heapq
import itertools
import re
import time
from dataclasses import dataclass, field

from .core import Param, Result, ToolError, clean_ws, pretty_hex, to_bytes, to_text, tool
from .language import (describe, index_of_coincidence, readability,
                       structure_hint)

MAX_BYTES = 200_000


# --------------------------------------------------------------------------
# Candidates
# --------------------------------------------------------------------------

@dataclass(order=True)
class Node:
    sort_key: float
    seq: int = field(compare=True)
    value: object = field(compare=False, default=None)
    steps: tuple = field(compare=False, default=())
    depth: int = field(compare=False, default=0)
    score: float = field(compare=False, default=0.0)
    certainty: float = field(compare=False, default=1.0)

    def recipe(self):
        return " -> ".join(s for s in self.steps)


def _as_text(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value)


def _as_bytes(value) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return str(value).encode("utf-8", errors="replace")


def _normalise(value):
    """Bytes that are plainly text become text, so the text transforms apply."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
        if text and printable / len(text) > 0.92:
            return text
        return raw
    return value


def _key(value):
    return (b"B" + value) if isinstance(value, bytes) else ("S" + value).encode("utf-8", "replace")


# --------------------------------------------------------------------------
# Shape tests - cheap gates so a transform only runs where it could work
# --------------------------------------------------------------------------

def _letters(text):
    return "".join(c for c in text if c.isalpha())


def _mostly_letters(text, threshold=0.55):
    if not text:
        return False
    return len(_letters(text)) / len(text) >= threshold


def _only(text, allowed, minimum=6):
    body = clean_ws(text)
    return len(body) >= minimum and all(c in allowed for c in body)


# --------------------------------------------------------------------------
# Transforms
# --------------------------------------------------------------------------

TRANSFORMS = []


def transform(name, kind="decode", involution=False, weight=None):
    """kind: 'decode' (deterministic) or 'brute' (sweeps a key space).

    `weight` is how much to believe the step. A Base64 decode that succeeds is
    a fact - the data really was Base64. An affine decode with a guessed key is
    a guess, and a wrong guess produces letters with much the same statistics
    as a right one. Without this distinction the search follows whichever
    garbage happens to score a fraction higher and never gets to the answer.
    """
    def wrap(fn):
        fn.tname, fn.kind, fn.involution = name, kind, involution
        fn.weight = weight if weight is not None else (1.0 if kind == "decode" else 0.30)
        TRANSFORMS.append(fn)
        return fn
    return wrap


def _looks_encoded(text) -> bool:
    """Mixed case, digits and no spaces: the shape of an encoding, not of a
    classical cipher. Letter-shuffling transforms should leave it alone."""
    body = clean_ws(text)
    if len(body) < 12 or " " in text.strip():
        return False
    return (any(c.isdigit() for c in body) and any(c.islower() for c in body)
            and any(c.isupper() for c in body)) or bool(re.fullmatch(r"[0-9a-fA-F]+", body))


# ---- representation changes -----------------------------------------------

@transform("Zero-width characters")
def _t_zero_width(text, raw):
    """Invisible Unicode characters carrying a message between the visible ones."""
    hidden = [c for c in text if c in "\u200b\u200c"]
    if len(hidden) < 16:
        return []
    bits = "".join("1" if c == "\u200c" else "0" for c in hidden)
    out = bytes(int(bits[i:i + 8].ljust(8, "0"), 2) for i in range(0, len(bits), 8))
    found = [("Zero-width characters", out)]
    try:
        from .stego import _unwrap
        found.insert(0, ("Zero-width characters", _unwrap(out, "")))
    except Exception:
        pass
    return found


@transform("Base64")
def _t_base64(text, raw):
    import base64 as b64
    body = clean_ws(text).replace("-", "+").replace("_", "/")
    if len(body) < 8 or not re.fullmatch(r"[A-Za-z0-9+/=]+", body):
        return []
    if len(body.rstrip("=")) % 4 == 1:
        return []
    try:
        out = b64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except Exception:
        return []
    return [("Base64", out)] if out else []


@transform("Base32")
def _t_base32(text, raw):
    import base64 as b64
    body = clean_ws(text).upper()
    if len(body) < 8 or not re.fullmatch(r"[A-Z2-7=]+", body):
        return []
    try:
        return [("Base32", b64.b32decode(body + "=" * (-len(body) % 8)))]
    except Exception:
        return []


@transform("Hex")
def _t_hex(text, raw):
    body = clean_ws(text).lower().replace("0x", "")
    if len(body) < 6 or len(body) % 2 or not re.fullmatch(r"[0-9a-f]+", body):
        return []
    return [("Hex", bytes.fromhex(body))]


@transform("Base85")
def _t_base85(text, raw):
    import base64 as b64
    body = clean_ws(text)
    if len(body) < 8 or not re.fullmatch(r"[!-u]+", body):
        return []
    out = []
    for label, fn in (("Ascii85", b64.a85decode), ("Base85", b64.b85decode)):
        try:
            got = fn(body)
            if got:
                out.append((label, got))
        except Exception:
            continue
    return out[:1]


@transform("Base58")
def _t_base58(text, raw):
    from .encodings import b58decode
    body = clean_ws(text)
    if not (8 <= len(body) <= 200) or not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", body):
        return []
    if body.isalpha() and body.islower():          # an ordinary word, not Base58
        return []
    try:
        return [("Base58", b58decode(body))]
    except Exception:
        return []


@transform("Base62")
def _t_base62(text, raw):
    from .encodings import B62, _bn_dec
    body = clean_ws(text)
    if not (8 <= len(body) <= 120) or not re.fullmatch(r"[0-9A-Za-z]+", body):
        return []
    if not (any(c.isdigit() for c in body) and any(c.isalpha() for c in body)):
        return []
    try:
        return [("Base62", _bn_dec(body, B62))]
    except Exception:
        return []


@transform("URL encoding")
def _t_url(text, raw):
    import urllib.parse
    if not re.search(r"%[0-9a-fA-F]{2}", text):
        return []
    out = urllib.parse.unquote_plus(text)
    return [("URL decode", out)] if out != text else []


@transform("HTML entities")
def _t_html(text, raw):
    import html as _html
    if not re.search(r"&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]{2,10});", text):
        return []
    out = _html.unescape(text)
    return [("HTML entities", out)] if out != text else []


@transform("Quoted-printable")
def _t_quopri(text, raw):
    import quopri
    if len(re.findall(r"=[0-9A-F]{2}", text)) < 2:
        return []
    try:
        out = quopri.decodestring(text.encode())
    except Exception:
        return []
    return [("Quoted-printable", out)] if out and out != raw else []


@transform("Escapes")
def _t_escapes(text, raw):
    from .encodings import _udesc
    if not re.search(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[nrt0]", text):
        return []
    try:
        out = _udesc(text)
    except Exception:
        return []
    return [("Unicode escapes", out)] if out != text else []


@transform("Binary")
def _t_binary(text, raw):
    from .encodings import _numbase_dec
    body = clean_ws(text)
    if len(body) < 16 or not re.fullmatch(r"[01]+", body):
        return []
    if len(body) % 8 == 0:
        try:
            return [("Binary", _numbase_dec(text, "binary"))]
        except Exception:
            return []
    return []


@transform("Decimal bytes")
def _t_decimal(text, raw):
    from .encodings import _numbase_dec
    toks = re.findall(r"\d+", text)
    if len(toks) < 4 or not re.fullmatch(r"[\d\s,]+", text.strip()):
        return []
    out = []
    if all(0 <= int(t) <= 255 for t in toks):
        try:
            out.append(("Decimal bytes", _numbase_dec(text, "decimal")))
        except Exception:
            pass
    if all(0 <= int(t) <= 377 for t in toks) and all(c in "01234567" for t in toks for c in t):
        try:
            out.append(("Octal bytes", _numbase_dec(text, "octal")))
        except Exception:
            pass
    return out


@transform("A1Z26")
def _t_a1z26(text, raw):
    from .encodings import _a1z26_dec
    toks = re.findall(r"\d+", text)
    if len(toks) < 3 or not re.fullmatch(r"[\d\s,;/|.\-]+", text.strip()):
        return []
    if not all(1 <= int(t) <= 26 for t in toks):
        return []
    return [("A1Z26", _a1z26_dec(text))]


@transform("Morse")
def _t_morse(text, raw):
    from .encodings import _morse_dec
    body = re.sub(r"[\s/|]", "", text.replace("·", ".").replace("–", "-").replace("_", "-"))
    if len(body) < 4 or set(body) - {".", "-"}:
        return []
    return [("Morse", _morse_dec(text))]


@transform("Bacon")
def _t_bacon(text, raw):
    from .encodings import _bacon_dec
    body = clean_ws(text).upper()
    if len(body) < 10 or len(body) % 5 or set(body) - {"A", "B"}:
        return []
    return [("Bacon", _bacon_dec(text))]


@transform("Baudot")
def _t_baudot(text, raw):
    from .encodings import _baudot_dec
    body = clean_ws(text)
    if len(body) < 15 or len(body) % 5 or set(body) - {"0", "1"}:
        return []
    return [("Baudot / ITA2", _baudot_dec(text))]


@transform("Tap code")
def _t_tap(text, raw):
    from .encodings import _tap_dec
    body = clean_ws(text)
    if len(body) < 4:
        return []
    if re.fullmatch(r"[1-5]+", body) and len(body) % 2 == 0:
        return [("Tap / Polybius", _tap_dec(text))]
    if set(body) <= {".", "/"} and body.count(".") >= 4:
        return [("Tap code", _tap_dec(text))]
    return []


@transform("Braille")
def _t_braille(text, raw):
    from .encodings import _braille_dec
    body = clean_ws(text)
    if len(body) < 3 or not all("⠀" <= c <= "⣿" for c in body):
        return []
    return [("Braille", _braille_dec(text))]


@transform("UUencode")
def _t_uu(text, raw):
    from .encodings import _uu_dec
    if "begin " not in text.lower():
        return []
    try:
        return [("UUencode", _uu_dec(text))]
    except Exception:
        return []


@transform("Decompress")
def _t_decompress(text, raw):
    from .encodings import decompress_bytes, sniff_compression
    if len(raw) < 10:
        return []
    if sniff_compression(raw) is None and raw[:1] not in (b"\x78",):
        return []
    out, used = decompress_bytes(raw)
    return [(f"Decompress ({used})", out)] if out else []


# ---- rotations and simple substitutions ------------------------------------

@transform("ROT47", involution=True)
def _t_rot47(text, raw):
    from .encodings import _rot47
    printable = sum(1 for c in text if 33 <= ord(c) <= 126)
    if len(text) < 6 or printable / len(text) < 0.6:
        return []
    return [("ROT47", _rot47(text))]


@transform("Atbash", involution=True)
def _t_atbash(text, raw):
    if _looks_encoded(text):
        return []
    from .classical import _atbash
    if not _mostly_letters(text, 0.4) or len(_letters(text)) < 6:
        return []
    return [("Atbash", _atbash(text))]


@transform("Reverse", involution=True)
def _t_reverse(text, raw):
    if len(text) < 6 or len(text) > 20000:
        return []
    return [("Reverse", text[::-1])]


@transform("Caesar", kind="brute")
def _t_caesar(text, raw):
    from .classical import _shift_char
    if not _mostly_letters(text, 0.4) or len(_letters(text)) < 6:
        return []
    shifted = [(n, "".join(_shift_char(c, -n) for c in text)) for n in range(1, 26)]
    if _looks_encoded(text):
        # ROT13 wrapped round Base64 is a real habit, so do not refuse outright.
        # But every shift of a Base64 string is still made of Base64 characters,
        # so "does it decode" cannot tell the shifts apart - look one step
        # further and ask what the decode actually produces.
        ranked = sorted(((_lookahead(c), n, c) for n, c in shifted), reverse=True)
        return [(f"Caesar shift {n}", c) for sc, n, c in ranked[:2] if sc > 0.0]
    scored = sorted(((readability(c), n, c) for n, c in shifted), reverse=True)
    return [(f"Caesar shift {n}", cand) for _s, n, cand in scored[:2]]


@transform("Affine", kind="brute")
def _t_affine(text, raw):
    if _looks_encoded(text):
        return []
    from .classical import _affine
    if not _mostly_letters(text, 0.5) or len(_letters(text)) < 12:
        return []
    scored = []
    for a in (3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
        for b in range(26):
            try:
                cand = _affine(text, a, b, True)
            except Exception:
                continue
            scored.append((readability(cand), a, b, cand))
    scored.sort(reverse=True)
    return [(f"Affine a={a} b={b}", cand) for _s, a, b, cand in scored[:2]]


@transform("Rail fence", kind="brute")
def _t_railfence(text, raw):
    if _looks_encoded(text):
        return []
    from .classical import _rail
    body = clean_ws(text)
    if len(body) < 10 or len(body) > 6000 or not _mostly_letters(body, 0.6):
        return []
    scored = []
    for rails in range(2, min(13, len(body) // 2)):
        try:
            cand = _rail(body, rails, 0, True)
        except Exception:
            continue
        scored.append((readability(cand), rails, cand))
    scored.sort(reverse=True)
    return [(f"Rail fence, {r} rails", cand) for _s, r, cand in scored[:2]]


@transform("Scytale", kind="brute")
def _t_scytale(text, raw):
    if _looks_encoded(text):
        return []
    from .classical import _scytale
    body = clean_ws(text)
    if len(body) < 10 or len(body) > 6000 or not _mostly_letters(body, 0.6):
        return []
    scored = []
    for n in range(2, min(25, len(body) // 2)):
        try:
            cand = _scytale(body, n, True)
        except Exception:
            continue
        scored.append((readability(cand), n, cand))
    scored.sort(reverse=True)
    return [(f"Scytale, {n} per turn", cand) for _s, n, cand in scored[:2]]


@transform("Single-byte XOR", kind="brute", weight=0.45)
def _t_xor_single(text, raw):
    if not (4 <= len(raw) <= 40000):
        return []
    from .analysis import _identify_magic
    from .encodings import decompress_bytes, sniff_compression
    scored = []
    for k in range(1, 256):
        cand = bytes(b ^ k for b in raw)
        printable = all(32 <= b < 127 or b in (9, 10, 13) for b in cand[:400])
        bonus = 0.0
        # A zlib header is only two bytes and a checksum, so random data passes
        # the test often enough to drown the real answer. Confirm it by
        # actually decompressing - cheap, since only a handful get this far.
        if sniff_compression(cand) and decompress_bytes(cand)[0] is not None:
            bonus = 0.75
        elif _identify_magic(cand):
            bonus = 0.50
        elif not printable:
            continue
        scored.append((readability(cand) + bonus, k, cand))
    scored.sort(key=lambda t: (-t[0], t[1]))
    return [(f"XOR 0x{k:02x}", cand) for _s, k, cand in scored[:2]]


@transform("Repeating-key XOR", kind="brute", weight=0.5)
def _t_xor_repeating(text, raw):
    from .classical import _xor_crack
    if not (32 <= len(raw) <= 40000):
        return []
    if readability(raw) > 0.30:        # already readable: nothing to recover
        return []
    try:
        res = _xor_crack(raw, min(16, max(2, len(raw) // 6)), "raw text/bytes")
    except Exception:
        return []
    key = re.search(r"Best key: b?['\"](.*)['\"]", res.note or "")
    label = f"Repeating XOR key {key.group(1)[:20]!r}" if key else "Repeating-key XOR"
    return [(label, res.data or res.text)]


@transform("Vigenere", kind="brute", weight=0.55)
def _t_vigenere(text, raw):
    from .classical import _vig_solve
    letters = _letters(text).upper()
    if len(letters) < 40:
        return []
    ioc = index_of_coincidence(letters)
    if ioc > 0.058:                    # that is a substitution, not a Vigenere
        return []
    try:
        res = _vig_solve(text, 20)
    except Exception:
        return []
    key = re.search(r"Best key: ([A-Z]+)", res.note or "")
    return [(f"Vigenere key {key.group(1)}" if key else "Vigenere", res.text)]


@transform("Substitution", kind="brute", weight=0.5)
def _t_substitution(text, raw):
    letters = _letters(text).upper()
    if len(letters) < 80:
        return []
    if index_of_coincidence(letters) < 0.055:
        return []
    best = _hillclimb_substitution(text)
    return [("Substitution (solved)", best)] if best else []


def _hillclimb_substitution(text, rounds=6):
    """Recover a monoalphabetic substitution by hill-climbing the key.

    Slow next to the other transforms, so it only runs on text long enough for
    the statistics to mean anything, and only when the index of coincidence
    says a substitution is what this is.
    """
    import random
    from .language import ALPHA, letter_loglik
    letters = _letters(text).upper()
    if len(letters) < 80:
        return None
    rng = random.Random(11)
    best_key, best_fit = None, -1e9
    for _round in range(rounds):
        key = list(ALPHA)
        rng.shuffle(key)
        table = {ALPHA[i]: key[i] for i in range(26)}
        fit = letter_loglik("".join(table[c] for c in letters))
        improved = True
        while improved:
            improved = False
            for i in range(26):
                for j in range(i + 1, 26):
                    key[i], key[j] = key[j], key[i]
                    table = {ALPHA[k]: key[k] for k in range(26)}
                    cand = letter_loglik("".join(table[c] for c in letters))
                    if cand > fit:
                        fit, improved = cand, True
                    else:
                        key[i], key[j] = key[j], key[i]
        if fit > best_fit:
            best_fit, best_key = fit, list(key)
    if best_key is None:
        return None
    table = {ALPHA[i]: best_key[i] for i in range(26)}
    out = []
    for c in text:
        if c.isupper():
            out.append(table.get(c, c))
        elif c.islower():
            out.append(table.get(c.upper(), c.upper()).lower())
        else:
            out.append(c)
    return "".join(out)


# --------------------------------------------------------------------------
# The search
# --------------------------------------------------------------------------

_QUICK_DECODERS = ("Base64", "Base32", "Hex", "Base85", "Base58", "Base62",
                   "URL encoding", "HTML entities", "Quoted-printable", "Escapes",
                   "Binary", "Decimal bytes", "A1Z26", "Morse", "Bacon", "Baudot",
                   "Tap code", "Braille", "UUencode", "Decompress")


def _decodable(value) -> bool:
    """Would any deterministic decoder bite on this? Used to steer the search
    down encoding chains rather than wandering through cipher keys."""
    text = _as_text(value)
    raw = _as_bytes(value)
    for fn in TRANSFORMS:
        if fn.tname not in _QUICK_DECODERS:
            continue
        try:
            if fn(text, raw):
                return True
        except Exception:
            continue
    return False


def _lookahead(value) -> float:
    """Best readability reachable by running one deterministic decoder.

    Recognisable binary - a compression header, a file's magic bytes - counts
    as a strong result even though it is not readable text, because it says
    the layer underneath was decoded correctly.
    """
    from .analysis import _identify_magic
    from .encodings import decompress_bytes, sniff_compression
    text = _as_text(value)
    raw = _as_bytes(value)
    bulk = ("Base64", "Base32", "Hex", "Base85", "Base58", "Base62",
            "URL encoding", "Decompress")
    best = 0.0
    for fn in TRANSFORMS:
        if fn.tname not in bulk:
            continue
        try:
            produced = fn(text, raw)
        except Exception:
            continue
        for _label, out in produced or []:
            if out is None:
                continue
            got = _as_bytes(out)
            score = readability(out)
            if sniff_compression(got) and decompress_bytes(got)[0] is not None:
                score += 0.55
            elif _identify_magic(got):
                score += 0.40
            best = max(best, score)
    return best


def solve(data, max_depth=4, seconds=12.0, thorough=False, want=8, min_score=0.33):
    """Best-first search for whatever chain of operations makes this readable."""
    start_value = _normalise(data if isinstance(data, (bytes, bytearray)) else to_text(data))
    if isinstance(start_value, bytes) and len(start_value) > MAX_BYTES:
        raise ToolError(f"That is {len(start_value):,} bytes - too big to search. "
                        "Auto-solve is for messages, not files.")
    if not _as_text(start_value).strip():
        raise ToolError("Nothing to solve.")

    root_readability = readability(start_value)
    if root_readability >= 0.55:
        node = Node(0.0, 0, start_value, ("already readable",), 0, root_readability, 1.0)
        return [node], 0, False

    deadline = time.time() + max(2.0, float(seconds))
    counter = itertools.count()
    seen = {_key(start_value)}
    root_score = readability(start_value)
    queue = [Node(-root_score, next(counter), start_value, (), 0, root_score, 1.0)]
    results = []
    expanded = 0
    node_budget = 900 if thorough else 320

    active = [t for t in TRANSFORMS
              if thorough or t.tname not in ("Substitution",)]

    # A result this good means the puzzle is solved; keep going only long
    # enough to finish the node in hand, rather than burning the time limit.
    STRONG = 0.60

    while queue and time.time() < deadline and expanded < node_budget:
        node = heapq.heappop(queue)
        expanded += 1
        if node.depth >= max_depth:
            continue
        # Do not keep mangling something that already reads as an answer
        if node.depth > 0 and node.score >= 0.55:
            continue
        text = _as_text(node.value)
        raw = _as_bytes(node.value)
        if len(raw) > MAX_BYTES:
            continue
        # Deterministic decoders first: they are cheap, and following an
        # encoding chain is almost always the right move before brute force.
        for fn in sorted(active, key=lambda f: 0 if f.kind == "decode" else 1):
            if time.time() > deadline:
                break
            if fn.involution and node.steps and node.steps[-1].startswith(fn.tname):
                continue
            try:
                produced = fn(text, raw)
            except Exception:
                continue
            for label, out in produced or []:
                if out is None:
                    continue
                out = _normalise(out)
                if not _as_text(out).strip():
                    continue
                k = _key(out)
                if k in seen:
                    continue
                seen.add(k)
                score = readability(out)
                steps = node.steps + (label,)
                certainty = node.certainty * fn.weight
                # Priority: how readable it is, how much the steps so far are
                # facts rather than guesses, plus a push for anything another
                # decoder can obviously take a bite out of - less a small
                # charge per step so short recipes win ties.
                priority = (score + 0.55 * certainty
                            + (0.15 if _decodable(out) else 0.0)
                            - 0.04 * len(steps))
                child = Node(-priority, next(counter), out, steps,
                             node.depth + 1, score, certainty)
                if score >= min_score:
                    results.append(child)
                heapq.heappush(queue, child)
        if not thorough and any(r.score >= STRONG for r in results):
            break

    results.sort(key=lambda n: (-n.score, -n.certainty, len(n.steps)))
    # keep the shortest recipe for any given answer
    unique, kept = [], set()
    for r in results:
        k = _as_text(r.value)[:400]
        if k in kept:
            continue
        kept.add(k)
        unique.append(r)
    return unique[:want], expanded, time.time() > deadline


# --------------------------------------------------------------------------
# The tool
# --------------------------------------------------------------------------

EXPLAIN = (
    "Paste something you cannot read and press the button. Cryptex tries everything it "
    "reasonably can, in every order it reasonably can, and shows you what came out.\n\n"
    "It works in layers, because real puzzles are layered. At each step it tries the "
    "decoders whose shape matches what it is holding - Base64, hex, Base32, Base58, Base62, "
    "Base85, URL and HTML escapes, quoted-printable, binary, decimal, octal, A1Z26, Morse, "
    "Bacon, Baudot, tap code, Braille, uuencode, and gzip/zlib/bzip2/xz - then feeds each "
    "result back in and tries again.\n\n"
    "Alongside those it sweeps the key spaces small enough to sweep: all 25 Caesar shifts, "
    "all 312 affine keys, Atbash, ROT47, rail fences up to twelve rails, scytale up to "
    "twenty-four, every one of the 255 single-byte XOR keys, and the statistical solvers "
    "for repeating-key XOR and Vigenere. Turn on 'thorough' and it will also hill-climb a "
    "full 26-letter substitution key, which needs a paragraph or so to work on.\n\n"
    "Everything that comes out is scored for how much it reads like a finished answer - "
    "recognisable structure such as JSON or a PEM block, or actual English words, including "
    "when the spaces are missing, as they are after a classical cipher. The results are "
    "ranked by that score and each one shows the exact recipe, so you can repeat it by hand "
    "in the individual tools."
)


def _auto_solve(data, depth=4, seconds=12, thorough=False, show=8):
    found, expanded, timed_out = solve(data, int(depth), float(seconds),
                                       bool(thorough), int(show))
    if not found:
        return Result(
            warn="No readable answer found.",
            note=(f"Tried {expanded} combinations. "
                  "If it is properly encrypted rather than encoded, there is nothing to find "
                  "without the key - check Entropy & randomness. Otherwise try 'thorough', a "
                  "greater depth, or give it more text: the solvers need something to work with."))
    if len(found) == 1 and found[0].steps == ("already readable",):
        return Result(text=_as_text(found[0].value),
                      note=f"Nothing to undo - this is already {describe(found[0].value)}. "
                           "If you expected it to be encoded, check you pasted the right thing.")
    rows = []
    for node in found:
        preview = _as_text(node.value).replace("\n", " ")[:110]
        rows.append((f"{node.score * 100:.0f}%", node.recipe(), describe(node.value), preview))
    best = found[0]
    note = (f"Best: {best.recipe()}  ->  {describe(best.value)} "
            f"({best.score * 100:.0f}% confident). {expanded} combinations tried"
            + (", stopped on the time limit" if timed_out else "") + ".")
    value = best.value
    text = _as_text(value)
    if isinstance(value, bytes) and not text.isprintable():
        text = pretty_hex(value)
    return Result(text=text, data=_as_bytes(value), rows=rows,
                  headers=["Confidence", "Recipe", "Looks like", "Result"],
                  prefer="text", note=note)


tool(id="auto-solve", name="Auto-solve", category="Identify",
     summary="Try everything, in every order, and rank what comes out",
     explain=EXPLAIN,
     example="Base64 of a Caesar shift of a reversed message - one button",
     tags=["solve", "crack", "brute force", "bruteforce", "auto", "decode", "ctf",
           "puzzle", "layers", "chain", "magic"],
     params=[Param("depth", "Maximum layers", "int", 4, minimum=1, maximum=8,
                   help="How many operations deep to go. 4 covers almost everything."),
             Param("seconds", "Time limit (seconds)", "int", 12, minimum=2, maximum=120),
             Param("thorough", "Thorough", "bool", False,
                   help="Searches much wider and adds the substitution solver. Slower."),
             Param("show", "Answers to list", "int", 8, minimum=1, maximum=40)],
     action=lambda d, depth=4, seconds=12, thorough=False, show=8:
         _auto_solve(d, depth, seconds, thorough, show),
     action_label="Solve it",
     binary_ok=True)
