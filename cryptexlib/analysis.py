"""Analysis — what is this, and what is it made of?"""
from __future__ import annotations

import math
import re
from collections import Counter

from .classical import (ALPHA, ENGLISH_FREQ, byte_english_score, chi_english,
                        english_score, index_of_coincidence, letter_loglik)
from .core import (Param, Result, ToolError, b64_any, clamp, clean_ws, pretty_hex,
                   strip_non_alpha, to_bytes, to_text, tool)

CAT = "Analysis"

tool(id="freq", name="Frequency analysis", category=CAT,
     summary="Letter, bigram and trigram counts with a bar chart",
     explain=("The first thing to do with an unknown cipher. If the letter counts have the "
              "lumpy shape of English (E, T, A, O tall; J, Q, X, Z tiny) but the letters are "
              "wrong, you are looking at a substitution cipher. If they are flat, it is either "
              "a polyalphabetic cipher, a transposition, or genuinely random data."),
     tags=["histogram", "counts", "letters", "bigram"],
     params=[Param("unit", "Count", "choice", "letters",
                   choices=["letters", "bigrams", "trigrams", "words", "all characters"]),
             Param("top", "Show top N", "int", 30, minimum=5, maximum=200)],
     action=lambda d, unit="letters", top=30: _freq(to_text(d), unit, int(top)),
     action_label="Analyse")


def _freq(text, unit, top):
    top = clamp(top, 1, 500, 30)
    if unit == "letters":
        items = [c for c in text.upper() if c in ALPHA]
    elif unit == "bigrams":
        s = strip_non_alpha(text).upper()
        items = [s[i:i + 2] for i in range(len(s) - 1)]
    elif unit == "trigrams":
        s = strip_non_alpha(text).upper()
        items = [s[i:i + 3] for i in range(len(s) - 2)]
    elif unit == "words":
        items = [w for w in re.findall(r"[A-Za-z']+", text.upper())]
    else:
        items = list(text)
    if not items:
        raise ToolError("Nothing to count.")
    counts = Counter(items)
    total = sum(counts.values())
    peak = counts.most_common(1)[0][1]
    rows = []
    for item, n in counts.most_common(top):
        pct = 100.0 * n / total
        exp = ENGLISH_FREQ.get(item, None) if unit == "letters" else None
        bar = "█" * max(1, round(30 * n / peak))
        rows.append((repr(item)[1:-1] if unit == "all characters" else item,
                     n, f"{pct:.2f}%",
                     f"{exp:.2f}%" if exp is not None else "", bar))
    letters = strip_non_alpha(text).upper()
    ioc = index_of_coincidence(letters)
    verdict = ("looks like English or a simple substitution" if ioc > 0.060
               else "flat — polyalphabetic, transposition-of-random, or not English"
               if ioc < 0.045 else "in between — possibly a short or mixed text")
    return Result(rows=rows, headers=["Item", "Count", "Share", "English", ""],
                  note=(f"{total} {unit}, {len(counts)} distinct. "
                        f"Index of coincidence {ioc:.4f} ({verdict}). "
                        "English is about 0.067, random about 0.038."))


tool(id="entropy", name="Entropy & randomness", category=CAT,
     summary="How random is this really? Shannon entropy per byte",
     explain=("Eight bits per byte means every byte value is equally likely — that is what "
              "properly encrypted or compressed data looks like. English text sits around "
              "4.0–4.5, Base64 around 6, a JPEG or a ZIP close to 8.\n\n"
              "Use it to tell 'encrypted' from 'encoded': high entropy plus no structure is "
              "ciphertext; high entropy with a recognisable header is a compressed file."),
     tags=["shannon", "random", "bits"],
     action=lambda d, **k: _entropy(d), action_label="Measure", binary_ok=True)


def _entropy(data):
    raw = to_bytes(data)
    if not raw:
        raise ToolError("Nothing to measure.")
    counts = Counter(raw)
    n = len(raw)
    h = -sum((c / n) * math.log2(c / n) for c in counts.values())
    printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13)) / n
    if h > 7.5:
        verdict = "Essentially random — encrypted, compressed, or a proper key."
    elif h > 6.0:
        verdict = "High — Base64/Base32 of random data, or lightly structured binary."
    elif h > 4.8:
        verdict = "Moderate — structured binary, or text in a large alphabet."
    else:
        verdict = "Low — ordinary text or very repetitive data."
    rows = [("Bytes", n), ("Distinct byte values", len(counts)),
            ("Shannon entropy", f"{h:.3f} bits per byte"),
            ("Maximum possible", "8.000 bits per byte"),
            ("Printable share", f"{printable*100:.1f}%"),
            ("English-likeness", f"{byte_english_score(raw):+.2f} (higher = more like English)")]
    return Result(rows=rows, headers=["Measure", "Value"], note=verdict)


tool(id="hexdump", name="Hex dump / file inspector", category=CAT,
     summary="Offset, hex, ASCII — plus what the magic bytes say the file is",
     explain=("The classic side-by-side dump, with file-type detection from the first few "
              "bytes. Useful for confirming that the thing you just decoded really is a PNG, "
              "a ZIP or a PDF before you save it."),
     tags=["dump", "magic", "file type", "signature"],
     params=[Param("width", "Bytes per line", "int", 16, minimum=4, maximum=64),
             Param("limit", "Maximum bytes shown", "int", 4096, minimum=64, maximum=1_000_000)],
     action=lambda d, width=16, limit=4096: _hexdump(d, int(width), int(limit)),
     action_label="Dump", binary_ok=True, input_kind="text")

MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"), (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"), (b"GIF89a", "GIF image"), (b"BM", "BMP image"),
    (b"%PDF-", "PDF document"), (b"PK\x03\x04", "ZIP (also docx/xlsx/pptx/jar/apk)"),
    (b"PK\x05\x06", "Empty ZIP"), (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b", "GZIP"), (b"BZh", "BZIP2"), (b"\xfd7zXZ\x00", "XZ"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"), (b"\x7fELF", "ELF executable"),
    (b"MZ", "Windows PE executable"), (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"), (b"RIFF", "RIFF container (WAV/AVI/WEBP)"),
    (b"ID3", "MP3 with ID3 tag"), (b"OggS", "Ogg"), (b"fLaC", "FLAC audio"),
    (b"\xd0\xcf\x11\xe0", "Legacy Office (doc/xls/ppt)"), (b"SQLite format 3\x00", "SQLite database"),
    (b"-----BEGIN", "PEM key or certificate"), (b"ssh-rsa", "OpenSSH public key"),
    (b"{\"", "JSON"), (b"<?xml", "XML"), (b"<!DOCTYPE", "HTML"),
]


def _identify_magic(raw: bytes):
    for sig, name in MAGIC:
        if raw.startswith(sig):
            return name
    if raw[4:12] in (b"ftypisom", b"ftypmp42") or raw[4:8] == b"ftyp":
        return "MP4/MOV container"
    return None


def _hexdump(data, width, limit):
    width, limit = clamp(width, 1, 64, 16), clamp(limit, 16, 5_000_000, 4096)
    raw = to_bytes(data)
    kind = _identify_magic(raw)
    shown = raw[:limit]
    note = f"{len(raw)} bytes."
    if kind:
        note += f" Magic bytes say: {kind}."
    if len(raw) > limit:
        note += f" Showing the first {limit}."
    return Result(text=pretty_hex(shown, width), note=note, data=raw)


tool(id="kasiski", name="Kasiski examination", category=CAT,
     summary="Finds repeated sequences and the key lengths they imply",
     explain=("If the same word is encrypted by the same part of a repeating key twice, the "
              "same ciphertext appears twice. The distance between the two is a multiple of "
              "the key length — so the most common factor of all those distances is usually "
              "the key length itself. This is how Vigenère was finally broken in 1863."),
     tags=["vigenere", "repeat", "key length", "factor"],
     params=[Param("minlen", "Shortest repeat to count", "int", 3, minimum=2, maximum=10),
             Param("maxkey", "Report factors up to", "int", 25, minimum=2, maximum=60)],
     action=lambda d, minlen=3, maxkey=25: _kasiski(to_text(d), int(minlen), int(maxkey)),
     action_label="Examine")


def _kasiski(text, minlen, maxkey):
    minlen, maxkey = clamp(minlen, 2, 12, 3), clamp(maxkey, 2, 80, 25)
    s = strip_non_alpha(text).upper()
    if len(s) < minlen * 4:
        raise ToolError("Need more ciphertext than that.")
    positions = {}
    for size in range(minlen, minlen + 3):
        for i in range(len(s) - size + 1):
            positions.setdefault(s[i:i + size], []).append(i)
    factors = Counter()
    repeats = []
    for seq, pos in positions.items():
        if len(pos) < 2:
            continue
        for a, b in zip(pos, pos[1:]):
            dist = b - a
            repeats.append((seq, len(pos), dist))
            for f in range(2, maxkey + 1):
                if dist % f == 0:
                    factors[f] += 1
    if not factors:
        return Result(note="No repeated sequences found — either the text is short, "
                           "the key is as long as the message, or it is not a repeating-key cipher.")
    rows = [(f, n, "█" * max(1, round(24 * n / factors.most_common(1)[0][1])))
            for f, n in factors.most_common(15)]
    iocs = []
    for klen in range(1, min(maxkey, len(s) // 3) + 1):
        cols = [s[i::klen] for i in range(klen)]
        iocs.append((klen, sum(index_of_coincidence(c) for c in cols) / klen))
    best_ioc = max(iocs, key=lambda x: x[1])
    top = factors.most_common(1)[0][0]
    return Result(rows=rows, headers=["Possible key length", "Supporting distances", ""],
                  note=(f"Kasiski favours {top}. Index of coincidence favours {best_ioc[0]} "
                        f"({best_ioc[1]:.4f}). Found {len(repeats)} repeated sequences. "
                        "Try both in the Vigenère tool."))


tool(id="diff", name="Compare two texts", category=CAT,
     summary="Where do these differ, byte by byte?",
     explain=("Paste one in the input and the other in the box below. Shows the first "
              "differing position, how many bytes differ and the differing lines — useful when "
              "a checksum fails, or when a decode is nearly right."),
     tags=["compare", "diff", "difference"],
     params=[Param("other", "Compare against", "multiline", "")],
     action=lambda d, other="": _diff(to_text(d), other), action_label="Compare")


def _diff(a, b):
    if not b:
        raise ToolError("Put the second text in the 'Compare against' box.")
    ab, bb = a.encode(), b.encode()
    if ab == bb:
        return Result(note="Identical — same length, same bytes.")
    first = next((i for i, (x, y) in enumerate(zip(ab, bb)) if x != y), min(len(ab), len(bb)))
    ndiff = sum(1 for x, y in zip(ab, bb) if x != y) + abs(len(ab) - len(bb))
    import difflib
    delta = list(difflib.unified_diff(a.splitlines(), b.splitlines(),
                                      "input", "compare against", lineterm="", n=1))
    return Result(text="\n".join(delta[:400]),
                  rows=[("Length A", len(ab)), ("Length B", len(bb)),
                        ("First difference at byte", first),
                        ("Differing bytes", ndiff)],
                  headers=["Measure", "Value"], warn="They are different.")


# --------------------------------------------------------------------------
# Crib dragging
# --------------------------------------------------------------------------

def _crib_drag(data, crib="", input_format="auto", second="", limit=200):
    raw, how = _as_bytes(data, input_format)
    crib_b = to_bytes(crib)
    if not crib_b:
        raise ToolError("Type a crib - a word or phrase you think is in the message. "
                        "'the ', ' the ', 'flag{' and a likely name are all worth a go.")
    if len(crib_b) > len(raw):
        raise ToolError("The crib is longer than the data.")
    # the second message is written the same way as the first (hex, Base64...)
    other = _as_bytes(second, how)[0] if second and second.strip() else b""
    if other:
        # two messages under the same key: XOR them and the key disappears
        n = min(len(raw), len(other))
        raw = bytes(a ^ b for a, b in zip(raw[:n], other[:n]))

    rows, good = [], 0
    for off in range(len(raw) - len(crib_b) + 1):
        out = bytes(a ^ b for a, b in zip(raw[off:off + len(crib_b)], crib_b))
        score = _readable(out)
        rows.append((off, score, out))
    rows.sort(key=lambda r: -r[1])
    shown = []
    for off, score, out in rows[:int(clamp(limit, 1, 2000, 200))]:
        text = "".join(chr(c) if 32 <= c < 127 else "·" for c in out)
        shown.append((off, f"{score:.0%}", text))
        if score > 0.75:
            good += 1
    return Result(rows=shown, headers=["At", "Plausible", "What comes out"],
                  note=("Best guesses first. " +
                        ("The plausible ones near the top are where the crib probably sits; "
                         "what comes out is the other message - or the key - at that point."
                         if good else
                         "Nothing came out looking like English. Try a different crib, or a "
                         "longer one.")),
                  warn=None if not other else
                       "Comparing two messages: what you see is the *other* message at that "
                       "offset, not the key. XOR it back against the first to get the key.")


def _as_bytes(data, how):
    from .core import decode_as
    return decode_as(data, how)


def _readable(out: bytes) -> float:
    if not out:
        return 0.0
    score = 0.0
    for c in out:
        if 97 <= c <= 122 or c == 32:
            score += 1.0
        elif 65 <= c <= 90:
            score += 0.8
        elif 48 <= c <= 57 or c in b".,'!?-_:;()/":
            score += 0.5
        elif c in (10, 13, 9):
            score += 0.3
        else:
            score -= 0.6
    return max(0.0, score / len(out))


tool(id="crib-drag", name="Crib drag (XOR key reuse)", category=CAT,
     summary="Slides a guessed word along XOR'd data to find where it fits",
     explain=(
         "The oldest attack on a stream cipher, and it still works, because the mistake it "
         "punishes - using the same keystream twice - is one people keep making.\n\n"
         "XOR has a useful property: if you XOR the ciphertext with a guess at the "
         "plaintext, and the guess is right, out comes the key at that point. If the guess "
         "is wrong, out comes noise. So you take a likely word, slide it along the data one "
         "byte at a time, and look at what falls out. Readable English means you have "
         "found it, and now you have a piece of the key - which decrypts that part of "
         "*every* message sent under it, which gives you more plaintext, which gives you "
         "more key.\n\n"
         "Fill in the second box and it does the two-time-pad version instead. XOR two "
         "messages encrypted with the same keystream together and the key cancels out "
         "entirely, leaving one message XOR'd with the other - and now a crib in either "
         "one reveals the corresponding stretch of the other.\n\n"
         "Good cribs: ' the ', 'flag{', 'http', a name you expect, the standard opening of "
         "whatever kind of message this is."),
     example="Paste hex or base64 ciphertext; crib: ' the '",
     tags=["crib", "drag", "xor", "key reuse", "two-time pad", "stream cipher", "ctf"],
     params=[Param("crib", "Crib", "text", " the ", width=24,
                   help="A word or phrase you expect to find."),
             Param("input_format", "Input is", "choice", "auto",
                   choices=["auto", "hex", "base64", "raw text/bytes"]),
             Param("second", "Second message (optional)", "multiline", "", width=40,
                   help="Another ciphertext under the same key, for the two-time-pad "
                        "attack. Same format as the first."),
             Param("limit", "Show best", "int", 200, minimum=1, maximum=2000)],
     action=_crib_drag, action_label="Drag it", binary_ok=True)


# --------------------------------------------------------------------------
# Cipher identifier - "what kind of cipher is this?"
# --------------------------------------------------------------------------

def _cipher_id(data, **_k):
    from .language import index_of_coincidence
    raw = to_text(data).strip()
    if not raw:
        raise ToolError("Paste some ciphertext to identify.")
    up = raw.upper()
    letters = [c for c in up if c.isalpha() and c.isascii()]
    digits = [c for c in raw if c.isdigit()]
    nonspace = [c for c in raw if not c.isspace()]
    L = len(letters)
    distinct = sorted(set(letters))
    ndist = len(distinct)
    ioc = index_of_coincidence("".join(letters)) if L >= 20 else 0.0

    obs, cands = [], []      # cands = (confidence 0-100, name, why)

    def add(conf, name, why):
        cands.append((conf, name, why))

    frac_alpha = L / max(1, len(nonspace))
    frac_digit = len(digits) / max(1, len(nonspace))

    # --- all-digits family
    if frac_digit > 0.9 and len(digits) >= 6:
        obs.append(f"Almost all digits ({len(digits)}).")
        nums = re.findall(r"\d+", raw)
        if nums and all(1 <= int(n) <= 26 for n in nums):
            add(70, "A1Z26", "every number is between 1 and 26 - letters as their position.")
        if all(len(n) == 2 for n in nums) or (len(digits) % 2 == 0 and " " not in raw.strip()):
            add(55, "Polybius / Nihilist", "digits pair up into grid coordinates.")
        add(45, "Nihilist", "runs of two- and three-digit numbers suggest an additive key.")
        add(30, "Gronsfeld or a book cipher", "numbers could be shifts or word references.")
        return _cipher_id_result(obs, cands, ioc, L)

    # --- tiny alphabets
    if set(distinct) <= set("ADFGVX") and ndist >= 3:
        add(92, "ADFGVX", "uses only the six letters A D F G V X.")
    if set(distinct) <= set("ADFGX") and ndist >= 3:
        add(88, "ADFGX", "uses only A D F G X.")
    if ndist <= 5 and L >= 20:
        obs.append(f"Only {ndist} distinct letters - a 5-symbol alphabet.")
        add(60, "Polybius / Bifid / a 5×5-square cipher",
            "five symbols is the hallmark of coordinates on a 5×5 square.")
    if set(distinct) <= set("AB") and L >= 20:
        add(85, "Bacon's cipher", "only two symbols - classic Baconian A/B.")

    # --- morse-ish
    if set(nonspace) <= set(".-/") and len(nonspace) >= 6:
        add(90, "Morse code", "only dots, dashes and separators.")

    if not letters:
        obs.append("No letters to analyse.")
        return _cipher_id_result(obs, cands, ioc, L)

    # --- index of coincidence: the big fork
    if L >= 40:
        short = L < 80
        obs.append(f"Index of coincidence {ioc:.4f} "
                   f"(English ≈ 0.067, random ≈ 0.038)"
                   + ("  - but under ~100 letters this is noisy, so treat the split below "
                      "with caution." if short else "."))
        penalty = 15 if short else 0
        if ioc >= 0.056:
            obs.append("High IoC: the letter frequencies are English-shaped, so the letters "
                       "were kept and only moved or relabelled.")
            # transposition vs substitution: does the frequency profile match English?
            add(55 - penalty, "Monoalphabetic substitution (or Caesar/Atbash)",
                "letters one-for-one - try the substitution and Caesar tools.")
            add(50 - penalty, "Transposition (rail fence / columnar / scytale)",
                "if the letters are plain English but jumbled, they were only reordered.")
        elif ioc < 0.050:
            obs.append("Low IoC: the frequencies are flattened, the sign of several "
                       "alphabets in rotation.")
            add(65 - penalty, "Polyalphabetic (Vigenère / Beaufort / Porta)",
                "flattened frequencies - try the Vigenère solver.")
            add(35, "A stream or XOR cipher",
                "possible if this is really raw bytes rather than letters.")
        else:
            obs.append("Middling IoC - could be a short-key polyalphabetic or a fractionating "
                       "cipher (Bifid/Trifid) that partly flattens the profile.")
            add(45, "Short-key Vigenère, or Bifid/Trifid", "IoC between the two camps.")

    # --- digraph tell (Playfair / four-square): even length, no doubled pairs
    if L >= 20 and L % 2 == 0:
        pairs = ["".join(letters[i:i + 2]) for i in range(0, L, 2)]
        doubled = sum(1 for p in pairs if len(p) == 2 and p[0] == p[1])
        has_j = "J" in distinct
        if doubled == 0 and not has_j and ioc > 0.05:
            add(50, "Playfair / four-square (digraphic)",
                "even length, no doubled letters in a pair, and no J - the Playfair signature.")

    # --- Enigma / rotor tell: no letter equals itself is impossible to see without plaintext,
    # but 5-letter groups + all caps + no repeats-in-place is suggestive
    groups = raw.split()
    if len(groups) > 3 and all(len(g) == 5 for g in groups[:-1]) and frac_alpha > 0.98:
        add(45, "A rotor machine (Enigma) or a group-transmitted cipher",
            "sent in five-letter groups, all letters - the way machine traffic was radioed.")

    return _cipher_id_result(obs, cands, ioc, L)


def _cipher_id_result(obs, cands, ioc, L):
    cands.sort(key=lambda t: -t[0])
    seen, rows = set(), []
    for conf, name, why in cands:
        if name in seen:
            continue
        seen.add(name)
        rows.append((f"{conf}%", name, why))
    if not rows:
        rows.append(("-", "Unclear", "Not enough signal to call it. Try Auto-solve, which "
                     "runs the likely candidates for you."))
    note = ("Best guesses first - this reads the shape of the text, it does not decrypt it. "
            "Auto-solve will actually try the top candidates.")
    text = "What this looks like:\n\n" + "\n".join(f"  {c:>4}  {n}\n        {w}"
                                                   for c, n, w in rows)
    if obs:
        text += "\n\nWhat was measured:\n" + "\n".join("  - " + o for o in obs)
    return Result(text=text, rows=rows, headers=["Confidence", "Cipher", "Why"],
                  prefer="text", note=note)


tool(id="cipher-id", name="Identify the cipher", category=CAT,
     summary="Reads the shape of ciphertext and suggests which cipher it is",
     explain=(
         "When you are handed ciphertext with no clue what made it, this is the first thing to "
         "run. It measures the things that give a cipher away - the size of the alphabet, "
         "whether it is letters or numbers, the index of coincidence, whether the length "
         "factors neatly, whether letters pair up without doubles - and ranks the ciphers "
         "that fit.\n\n"
         "The index of coincidence is the workhorse: English text and anything that only "
         "moves or relabels letters (Caesar, substitution, transposition) keeps its bumpy "
         "letter frequencies, while anything using several alphabets at once (Vigenère and "
         "friends) flattens them. That one number splits the field in half.\n\n"
         "It reads the shape, it does not break the cipher - the confidences are honest "
         "guesses, and Auto-solve is the tool that actually tries them. Think of this as the "
         "triage step before that."),
     example="Paste a chunk of unknown ciphertext - the more the better, at least 40 letters.",
     tags=["identify", "cipher", "classify", "ioc", "triage", "unknown", "ctf"],
     action=_cipher_id, action_label="Identify", input_kind="text")
