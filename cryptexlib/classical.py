"""Classical ciphers — historical, breakable, and the fun half of the app.

Every one of these is broken. They are here to learn from, to solve puzzles
with, and to recognise when you meet one. Nothing here protects anything.
"""
from __future__ import annotations

import string

from .core import (ALPHA, Param, Result, ToolError, clamp, need, strip_non_alpha,
                   to_bytes, to_text, tool)

CAT = "Classical ciphers"

WARN = "Historical cipher — trivially broken. Never use it to protect anything real."
CHOSEN = "<- chosen"


def _shift_char(c, n):
    if "A" <= c <= "Z":
        return chr((ord(c) - 65 + n) % 26 + 65)
    if "a" <= c <= "z":
        return chr((ord(c) - 97 + n) % 26 + 97)
    return c


# --------------------------------------------------------------------------
# Shift family
# --------------------------------------------------------------------------

tool(id="caesar", name="Caesar / ROT-N shift", category=CAT,
     summary="Slide every letter N places along the alphabet",
     explain=("The oldest cipher there is. Pick a number 1–25; A becomes the letter N places "
              "later, wrapping Z round to A. ROT13 is just Caesar with N=13, which is why "
              "encoding and decoding are the same operation there.\n\n"
              "With only 25 possible keys you can break it by trying them all — use the "
              "'Caesar brute force' tool for that."),
     example="ATTACK AT DAWN, shift 3  ->  DWWDFN DW GDZQ",
     security=WARN, tags=["rot13", "shift", "rot", "julius"],
     params=[Param("shift", "Shift", "int", 3, minimum=-25, maximum=25,
                   help="13 gives ROT13. Negative shifts go the other way.")],
     encode=lambda d, shift=3: "".join(_shift_char(c, int(shift)) for c in to_text(d)),
     decode=lambda d, shift=3: "".join(_shift_char(c, -int(shift)) for c in to_text(d)))

tool(id="caesar-brute", name="Caesar brute force", category=CAT,
     summary="All 25 shifts at once, scored for how English they look",
     explain=("Prints every possible Caesar shift and ranks them by how closely the letter "
              "frequencies match English. The top row is almost always the answer."),
     security="", tags=["crack", "solve", "brute", "rot"],
     action=lambda d, **k: _caesar_brute(to_text(d)),
     action_label="Try all 25")


# The English-language model lives in language.py so that every solver in the
# app - here, the analysis tools, the identifier and the auto-solver - ranks
# candidates by exactly the same measure.
from .language import (BIGRAM_PCT, COMMON_WORDS, ENGLISH_FREQ,  # noqa: E402,F401
                       byte_english_score, chi_english, index_of_coincidence,
                       letter_loglik, readability, segment_coverage,
                       word_coverage)


def english_score(text: str) -> float:
    """Legacy scorer kept for the Caesar brute-force table: chi-squared fit
    plus a bonus for each common word that appears."""
    letters = [c for c in text.upper() if c in ALPHA]
    if not letters:
        return -999.0
    words = {w.strip(string.punctuation).upper() for w in text.split()}
    return chi_english(text) + 3.0 * len(words & COMMON_WORDS)


def _caesar_brute(text):
    rows = []
    for n in range(26):
        cand = "".join(_shift_char(c, -n) for c in text)
        rows.append((n, f"{english_score(cand):+.2f}", cand[:120]))
    rows.sort(key=lambda r: float(r[1]), reverse=True)
    best = rows[0]
    return Result(rows=rows, headers=["Shift", "English score", "Plaintext"],
                  text="".join(_shift_char(c, -best[0]) for c in text),
                  note=f"Best guess: shift {best[0]} (score {best[1]}). Full output above.")


tool(id="atbash", name="Atbash", category=CAT,
     summary="Mirror the alphabet — A↔Z, B↔Y",
     explain=("A Hebrew scribal cipher with no key at all: each letter is replaced by its "
              "mirror image in the alphabet. Self-inverse, so one button does both jobs."),
     example="HELLO  ->  SVOOL",
     security=WARN, tags=["mirror", "hebrew", "reverse alphabet"],
     encode=lambda d, **k: _atbash(to_text(d)), decode=lambda d, **k: _atbash(to_text(d)),
     encode_label="Apply", decode_label="Apply (same thing)")


def _atbash(t):
    out = []
    for c in t:
        if "A" <= c <= "Z":
            out.append(chr(155 - ord(c)))
        elif "a" <= c <= "z":
            out.append(chr(219 - ord(c)))
        else:
            out.append(c)
    return "".join(out)


tool(id="affine", name="Affine cipher", category=CAT,
     summary="Multiply then add: (a×letter + b) mod 26",
     explain=("A Caesar shift with a multiplication in front. 'a' must share no factor with 26 "
              "— that is, one of 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25 — otherwise two "
              "letters map onto one and it cannot be undone. a=1 gives plain Caesar."),
     example="a=5, b=8 — HELLO  ->  RCLLA",
     security=WARN, tags=["modular", "maths"],
     params=[Param("a", "a (multiplier)", "int", 5, help="Must be coprime with 26."),
             Param("b", "b (shift)", "int", 8)],
     encode=lambda d, a=5, b=8: _affine(to_text(d), int(a), int(b), False),
     decode=lambda d, a=5, b=8: _affine(to_text(d), int(a), int(b), True))


def _affine(text, a, b, dec):
    if a % 2 == 0 or a % 13 == 0:
        raise ToolError(f"a={a} shares a factor with 26 — pick from 1,3,5,7,9,11,15,17,19,21,23,25.")
    inv = pow(a, -1, 26)
    out = []
    for c in text:
        if "A" <= c <= "Z" or "a" <= c <= "z":
            base = 65 if c.isupper() else 97
            x = ord(c) - base
            y = (inv * (x - b)) % 26 if dec else (a * x + b) % 26
            out.append(chr(base + y))
        else:
            out.append(c)
    return "".join(out)


# --------------------------------------------------------------------------
# Keyword polyalphabetics
# --------------------------------------------------------------------------

def _keystream(key, text, autokey=False, plain=None):
    key = strip_non_alpha(key).upper()
    if not key:
        raise ToolError("This cipher needs a keyword.")
    return key


tool(id="vigenere", name="Vigenère cipher", category=CAT,
     summary="A Caesar shift per letter, driven by a repeating keyword",
     explain=("Each letter of the keyword gives the shift for one letter of the message, and "
              "the keyword repeats. Because the same plaintext letter encrypts differently "
              "depending on position, simple frequency counting fails — which is why it was "
              "called 'le chiffre indéchiffrable' for three hundred years.\n\n"
              "It is broken by finding the key length (repeated patterns in the ciphertext give "
              "it away) and then solving each position as a separate Caesar. The 'Vigenère "
              "solver' tool does exactly that."),
     example="key LEMON — ATTACKATDAWN  ->  LXFOPVEFRNHR",
     security=WARN, tags=["polyalphabetic", "keyword", "beaufort"],
     params=[Param("key", "Keyword", "text", "LEMON", width=20),
             Param("variant", "Variant", "choice", "Vigenère",
                   choices=["Vigenère", "Beaufort", "Variant Beaufort", "Autokey"]),
             Param("keep", "Keep punctuation and spacing", "bool", True)],
     encode=lambda d, key="LEMON", variant="Vigenère", keep=True:
         _vig(to_text(d), key, variant, keep, False),
     decode=lambda d, key="LEMON", variant="Vigenère", keep=True:
         _vig(to_text(d), key, variant, keep, True))


def _vig(text, key, variant, keep, dec):
    key = strip_non_alpha(key).upper()
    if not key:
        raise ToolError("Vigenère needs a keyword made of letters.")
    ks = [ord(c) - 65 for c in key]
    out, ki, produced = [], 0, []
    for c in text:
        if not ("A" <= c <= "Z" or "a" <= c <= "z"):
            if keep:
                out.append(c)
            continue
        base = 65 if c.isupper() else 97
        x = ord(c) - base
        k = ks[ki % len(ks)]
        if variant == "Beaufort":
            y = (k - x) % 26                       # self-inverse
        elif variant == "Variant Beaufort":
            y = (x + k) % 26 if dec else (x - k) % 26
        else:                                       # Vigenère / Autokey
            y = (x - k) % 26 if dec else (x + k) % 26
        out.append(chr(base + y))
        if variant == "Autokey":
            produced.append(y if dec else x)
            if ki + 1 >= len(ks):
                ks = ks + produced
                produced = []
        ki += 1
    return "".join(out)


tool(id="vigenere-solve", name="Vigenère solver", category=CAT,
     summary="Works out the key length and the key from ciphertext alone",
     explain=("Uses the index of coincidence to estimate the key length, then solves each "
              "key position as an independent Caesar by frequency analysis. Needs a few "
              "hundred letters of English to be reliable; short messages will guess wrong."),
     tags=["crack", "solve", "kasiski", "ioc"],
     params=[Param("maxlen", "Longest key to try", "int", 20, minimum=2, maximum=40)],
     action=lambda d, maxlen=20: _vig_solve(to_text(d), int(maxlen)),
     action_label="Solve")


def index_of_coincidence(letters):
    n = len(letters)
    if n < 2:
        return 0.0
    counts = {c: letters.count(c) for c in set(letters)}
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def _vig_solve(text, maxlen):
    """Try every key length, solve each, then pick with a description-length
    penalty so a *multiple* of the real key (which fits just as well) loses."""
    import math
    letters = strip_non_alpha(text).upper()
    if len(letters) < 20:
        raise ToolError("Not enough text - give it at least 20 letters, ideally a few hundred.")
    n = len(letters)
    per_key_letter = math.log(26) / n
    maxlen = clamp(maxlen, 1, 64, 20)
    cands = []
    for klen in range(1, min(maxlen, max(1, n // 3)) + 1):
        key = ""
        for i in range(klen):
            col = letters[i::klen]
            key += ALPHA[max(range(26),
                             key=lambda sh: chi_english("".join(_shift_char(c, -sh) for c in col)))]
        plain = _vig(letters, key, "Vigenere", True, True)
        fit = letter_loglik(plain)
        cols = [letters[i::klen] for i in range(klen)]
        ioc = sum(index_of_coincidence(c) for c in cols) / klen
        cands.append((klen, key, plain, fit - klen * per_key_letter, ioc))
    klen, key, plain, adj, ioc = max(cands, key=lambda c: c[3])
    # Refine: each key letter was chosen from its own column in isolation, which
    # goes wrong on short columns. Now hill-climb each position against the
    # bigram score of the WHOLE decryption, where neighbouring letters vote.
    key = list(key)
    for _round in range(4):
        improved = False
        for pos in range(klen):
            current = key[pos]
            best_letter, best_fit = current, letter_loglik(_vig(letters, "".join(key), "Vigenere", True, True))
            for cand in ALPHA:
                if cand == current:
                    continue
                key[pos] = cand
                fit = letter_loglik(_vig(letters, "".join(key), "Vigenere", True, True))
                if fit > best_fit:
                    best_letter, best_fit, improved = cand, fit, True
            key[pos] = best_letter
        if not improved:
            break
    key = "".join(key)
    full = _vig(text, key, "Vigenere", True, True)
    ranked = sorted(cands, key=lambda c: c[3], reverse=True)[:10]
    rows = [(c[0], c[1][:24], "%.4f" % c[4], "%+.3f" % c[3], c[2][:48],
             CHOSEN if c[0] == klen else "") for c in ranked]
    return Result(text=full, rows=rows,
                  headers=["Key length", "Key", "Index of coinc.", "Score", "Plaintext", ""],
                  note=("Best key: %s (length %d); index of coincidence %.4f. "
                        "English is about 0.067, random text 0.038." % (key, klen, ioc)))


tool(id="running-key", name="Running-key cipher", category=CAT,
     summary="Vigenère where the key is a whole book passage",
     explain=("Same arithmetic as Vigenère, but the key is as long as the message so there is "
              "no repetition to find. Still breakable, because the key is itself English."),
     security=WARN, tags=["book cipher", "long key"],
     params=[Param("key", "Key text", "multiline", "", help="Must be at least as long as the message.")],
     encode=lambda d, key="": _running(to_text(d), key, False),
     decode=lambda d, key="": _running(to_text(d), key, True))


def _running(text, key, dec):
    k = strip_non_alpha(key).upper()
    msg_len = len(strip_non_alpha(text))
    if len(k) < msg_len:
        raise ToolError(f"Key has {len(k)} letters but the message needs {msg_len}.")
    return _vig(text, k, "Vigenère", True, dec)


# --------------------------------------------------------------------------
# Grid ciphers
# --------------------------------------------------------------------------

def _polybius_square(key="", combine="J into I"):
    drop = "J" if combine.startswith("J") else "Q"
    seen, sq = [], []
    for c in (strip_non_alpha(key).upper() + ALPHA):
        if c == drop:
            c = "I" if drop == "J" else ""
        if c and c not in seen:
            seen.append(c)
    return seen[:25]


tool(id="polybius", name="Polybius square", category=CAT,
     summary="Each letter as a row/column pair in a 5×5 grid",
     explain=("Write the alphabet into a 5×5 grid (I and J share a cell) and give each letter "
              "its row and column number. It halves nothing and hides little, but it is the "
              "building block of Nihilist, ADFGVX and the tap code."),
     example="key=CRYPTO — H  ->  23",
     security=WARN, tags=["grid", "nihilist", "5x5"],
     params=[Param("key", "Keyword (optional)", "text", "", width=16),
             Param("combine", "Share a cell", "choice", "J into I", choices=["J into I", "Q dropped"]),
             Param("labels", "Row/column labels", "text", "12345", width=8)],
     encode=lambda d, key="", combine="J into I", labels="12345": _poly(to_text(d), key, combine, labels, False),
     decode=lambda d, key="", combine="J into I", labels="12345": _poly(to_text(d), key, combine, labels, True))


def _poly(text, key, combine, labels, dec):
    sq = _polybius_square(key, combine)
    labels = (labels or "12345")[:5]
    if len(labels) < 5:
        raise ToolError("Give five row/column labels, e.g. 12345 or ADFGX.")
    if not dec:
        out = []
        for c in text.upper():
            if combine.startswith("J") and c == "J":
                c = "I"
            if c in sq:
                i = sq.index(c)
                out.append(labels[i // 5] + labels[i % 5])
        return " ".join(out)
    toks = [t for t in text.upper().replace("\n", " ").split() if t]
    if len(toks) == 1:
        toks = [toks[0][i:i + 2] for i in range(0, len(toks[0]), 2)]
    out = ""
    for t in toks:
        if len(t) != 2 or t[0] not in labels or t[1] not in labels:
            out += "?"
            continue
        out += sq[labels.index(t[0]) * 5 + labels.index(t[1])]
    return out


tool(id="playfair", name="Playfair cipher", category=CAT,
     summary="Encrypts letter pairs in a 5×5 keyed grid — used in both world wars",
     explain=("The first practical digraph cipher: letters are encrypted two at a time using "
              "a keyed 5×5 square. Same row -> shift right; same column -> shift down; otherwise "
              "swap columns. Doubled letters in a pair get an X inserted, and an odd message "
              "gets an X on the end, so decoded text often has stray Xs in it."),
     example="key MONARCHY — HIDE  ->  BMOD",
     security=WARN, tags=["digraph", "wwi", "wwii", "5x5"],
     params=[Param("key", "Keyword", "text", "MONARCHY", width=20),
             Param("combine", "Share a cell", "choice", "J into I", choices=["J into I", "Q dropped"]),
             Param("filler", "Filler letter", "text", "X", width=4)],
     encode=lambda d, key="MONARCHY", combine="J into I", filler="X":
         _playfair(to_text(d), key, combine, filler, False),
     decode=lambda d, key="MONARCHY", combine="J into I", filler="X":
         _playfair(to_text(d), key, combine, filler, True))


def _playfair(text, key, combine, filler, dec):
    sq = _polybius_square(key, combine)
    filler = (strip_non_alpha(filler).upper() or "X")[0]
    letters = strip_non_alpha(text).upper()
    if combine.startswith("J"):
        letters = letters.replace("J", "I")
    else:
        letters = letters.replace("Q", "")
    letters = "".join(c for c in letters if c in sq)
    if not letters:
        raise ToolError("There are no letters here that Playfair can work with.")
    pairs = []
    i = 0
    if dec:
        if len(letters) % 2:
            raise ToolError("Playfair ciphertext must have an even number of letters.")
        pairs = [(letters[j], letters[j + 1]) for j in range(0, len(letters), 2)]
    else:
        while i < len(letters):
            a = letters[i]
            b = letters[i + 1] if i + 1 < len(letters) else filler
            if a == b:
                b = filler
                i += 1
            else:
                i += 2
            pairs.append((a, b))
    step = -1 if dec else 1
    out = []
    for a, b in pairs:
        ra, ca = divmod(sq.index(a), 5)
        rb, cb = divmod(sq.index(b), 5)
        if ra == rb:
            out.append(sq[ra * 5 + (ca + step) % 5])
            out.append(sq[rb * 5 + (cb + step) % 5])
        elif ca == cb:
            out.append(sq[((ra + step) % 5) * 5 + ca])
            out.append(sq[((rb + step) % 5) * 5 + cb])
        else:
            out.append(sq[ra * 5 + cb])
            out.append(sq[rb * 5 + ca])
    return "".join(out)


tool(id="adfgvx", name="ADFGX / ADFGVX", category=CAT,
     summary="German WWI field cipher — grid substitution plus column transposition",
     explain=("Letters become pairs from the letters A D F G V X (chosen because they sound "
              "unlike each other in Morse), then the whole lot is scrambled by a keyed "
              "columnar transposition. The two stages together resisted attack far better "
              "than either alone."),
     security=WARN, tags=["wwi", "german", "fractionating", "transposition"],
     params=[Param("square_key", "Square keyword", "text", "", width=16),
             Param("trans_key", "Transposition keyword", "text", "PRIVACY", width=16),
             Param("variant", "Variant", "choice", "ADFGVX (36, letters+digits)",
                   choices=["ADFGVX (36, letters+digits)", "ADFGX (25, letters only)"])],
     encode=lambda d, square_key="", trans_key="PRIVACY", variant="ADFGVX (36, letters+digits)":
         _adfgvx(to_text(d), square_key, trans_key, variant, False),
     decode=lambda d, square_key="", trans_key="PRIVACY", variant="ADFGVX (36, letters+digits)":
         _adfgvx(to_text(d), square_key, trans_key, variant, True))


def _adfgvx(text, square_key, trans_key, variant, dec):
    six = variant.startswith("ADFGVX")
    labels = "ADFGVX" if six else "ADFGX"
    size = 6 if six else 5
    pool = (ALPHA + "0123456789") if six else ALPHA.replace("J", "")
    seen = []
    for c in ("".join(ch for ch in square_key.upper() if ch.isalnum()) + pool):
        if not six and c == "J":
            c = "I"
        if c in pool and c not in seen:
            seen.append(c)
    sq = seen[:size * size]
    tkey = strip_non_alpha(trans_key).upper()
    if not tkey:
        raise ToolError("ADFGVX needs a transposition keyword.")
    order = sorted(range(len(tkey)), key=lambda i: (tkey[i], i))

    if not dec:
        frac = ""
        for c in text.upper():
            if not six and c == "J":
                c = "I"
            if c in sq:
                i = sq.index(c)
                frac += labels[i // size] + labels[i % size]
        cols = [[] for _ in tkey]
        for i, ch in enumerate(frac):
            cols[i % len(tkey)].append(ch)
        return " ".join("".join(cols[i]) for i in order)

    body = "".join(c for c in text.upper() if c in labels)
    n, k = len(body), len(tkey)
    base, extra = divmod(n, k)
    lens = [base + (1 if i < extra else 0) for i in range(k)]
    chunks, pos = {}, 0
    for idx in order:
        chunks[idx] = body[pos:pos + lens[idx]]
        pos += lens[idx]
    frac, ptr = "", [0] * k
    for i in range(n):
        c = i % k
        frac += chunks[c][ptr[c]]
        ptr[c] += 1
    out = ""
    for i in range(0, len(frac) - 1, 2):
        r, c = labels.index(frac[i]), labels.index(frac[i + 1])
        out += sq[r * size + c]
    return out


# --------------------------------------------------------------------------
# Transposition
# --------------------------------------------------------------------------

tool(id="railfence", name="Rail fence cipher", category=CAT,
     summary="Write in a zig-zag across N rails, read off row by row",
     explain=("Pure transposition: the letters are all still there, just reordered. Write the "
              "message diagonally down and up across a number of 'rails', then read each rail "
              "left to right. Very few keys, so it falls to brute force instantly."),
     example="3 rails — WEAREDISCOVERED  ->  WECRAERDSOEEVID",
     security=WARN, tags=["zigzag", "transposition"],
     params=[Param("rails", "Rails", "int", 3, minimum=2, maximum=40),
             Param("offset", "Starting offset", "int", 0, minimum=0, maximum=40)],
     encode=lambda d, rails=3, offset=0: _rail(to_text(d), int(rails), int(offset), False),
     decode=lambda d, rails=3, offset=0: _rail(to_text(d), int(rails), int(offset), True))


def _rail_pattern(n, rails, offset):
    pat, r, step = [], 0, 1
    for _ in range(offset):
        r += step
        if r == rails - 1 or r == 0:
            step = -step
    for _ in range(n):
        pat.append(r)
        if rails > 1:
            r += step
            if r == rails - 1 or r == 0:
                step = -step
    return pat


def _rail(text, rails, offset, dec):
    if rails < 2:
        raise ToolError("Need at least 2 rails.")
    pat = _rail_pattern(len(text), rails, offset)
    if not dec:
        return "".join(text[i] for r in range(rails) for i in range(len(text)) if pat[i] == r)
    out = [""] * len(text)
    it = iter(text)
    for r in range(rails):
        for i in range(len(text)):
            if pat[i] == r:
                out[i] = next(it)
    return "".join(out)


tool(id="columnar", name="Columnar transposition", category=CAT,
     summary="Write in rows under a keyword, read out in alphabetical key order",
     explain=("Write the message in rows the width of the keyword, then read the columns off "
              "in the order the keyword's letters come alphabetically. Double transposition "
              "(running it twice with two keywords) was a serious field cipher well into the "
              "twentieth century."),
     security=WARN, tags=["transposition", "keyword", "double"],
     params=[Param("key", "Keyword", "text", "ZEBRAS", width=16),
             Param("pad", "Pad character", "text", "X", width=4),
             Param("double", "Apply twice (double transposition)", "bool", False),
             Param("key2", "Second keyword", "text", "", width=16)],
     encode=lambda d, key="ZEBRAS", pad="X", double=False, key2="":
         _col_multi(to_text(d), key, pad, double, key2, False),
     decode=lambda d, key="ZEBRAS", pad="X", double=False, key2="":
         _col_multi(to_text(d), key, pad, double, key2, True))


def _col_multi(text, key, pad, double, key2, dec):
    if not double:
        return _columnar(text, key, pad, dec)
    k2 = key2 or key
    if dec:
        return _columnar(_columnar(text, k2, pad, True), key, pad, True)
    return _columnar(_columnar(text, key, pad, False), k2, pad, False)


def _columnar(text, key, pad, dec):
    key = "".join(c for c in key.upper() if c.isalnum())
    if not key:
        raise ToolError("Columnar transposition needs a keyword.")
    k = len(key)
    order = sorted(range(k), key=lambda i: (key[i], i))
    if not dec:
        body = "".join(text.split())
        padch = (pad or "X")[0]
        while len(body) % k:
            body += padch
        rows = [body[i:i + k] for i in range(0, len(body), k)]
        return "".join("".join(r[i] for r in rows) for i in order)
    body = "".join(text.split())
    nrows = -(-len(body) // k)
    lens = [nrows] * k
    short = nrows * k - len(body)
    # an unpadded message leaves the LAST columns of the grid short - by
    # position, not by alphabetical key order
    for i in reversed(range(k)):
        if short <= 0:
            break
        lens[i] -= 1
        short -= 1
    cols, pos = {}, 0
    for i in order:
        cols[i] = body[pos:pos + lens[i]]
        pos += lens[i]
    out = ""
    for r in range(nrows):
        for c in range(k):
            if r < len(cols[c]):
                out += cols[c][r]
    return out


tool(id="scytale", name="Scytale", category=CAT,
     summary="The Spartan rod — wrap a strip round a stick of diameter N",
     explain=("The oldest transposition device known. A leather strip wound round a rod of the "
              "right thickness lines the letters up; with the wrong rod it is gibberish. "
              "Mathematically it is a columnar transposition with an unkeyed column order."),
     security=WARN, tags=["sparta", "transposition", "rod"],
     params=[Param("n", "Letters per turn", "int", 4, minimum=2, maximum=100)],
     encode=lambda d, n=4: _scytale(to_text(d), int(n), False),
     decode=lambda d, n=4: _scytale(to_text(d), int(n), True))


def _scytale(text, n, dec):
    """Encoding reads the message off in n strands; decoding has to put the
    strands back in step. When the message length is not a whole multiple of
    n the strands are of unequal length, which is exactly the case a naive
    inverse gets wrong."""
    body = "".join(text.split())
    if n < 2:
        return body
    if not dec:
        return "".join(body[i::n] for i in range(n))
    total = len(body)
    lengths = [(total - i + n - 1) // n for i in range(n)]
    strands, pos = [], 0
    for length in lengths:
        strands.append(body[pos:pos + length])
        pos += length
    out = []
    for row in range(max(lengths) if lengths else 0):
        for i in range(n):
            if row < lengths[i]:
                out.append(strands[i][row])
    return "".join(out)


# --------------------------------------------------------------------------
# Substitution and XOR
# --------------------------------------------------------------------------

tool(id="substitution", name="Simple substitution", category=CAT,
     summary="Your own 26-letter alphabet, or one built from a keyword",
     explain=("Any one-to-one mapping of the alphabet. With 26! possible keys it looks strong, "
              "but letter frequencies survive intact, so a page of English falls to frequency "
              "analysis in minutes. Use the 'Frequency analysis' tool alongside it."),
     security=WARN, tags=["monoalphabetic", "keyword", "aristocrat"],
     params=[Param("alphabet", "Cipher alphabet (26 letters)", "text",
                   "QWERTYUIOPASDFGHJKLZXCVBNM", width=30),
             Param("keyword", "…or build it from a keyword", "text", "", width=16,
                   help="Keyword letters first, then the rest of the alphabet in order.")],
     encode=lambda d, alphabet="QWERTYUIOPASDFGHJKLZXCVBNM", keyword="":
         _subst(to_text(d), alphabet, keyword, False),
     decode=lambda d, alphabet="QWERTYUIOPASDFGHJKLZXCVBNM", keyword="":
         _subst(to_text(d), alphabet, keyword, True))


def _subst(text, alphabet, keyword, dec):
    if keyword.strip():
        seen = []
        for c in (strip_non_alpha(keyword).upper() + ALPHA):
            if c not in seen:
                seen.append(c)
        alphabet = "".join(seen)
    alphabet = strip_non_alpha(alphabet).upper()
    if len(alphabet) != 26 or len(set(alphabet)) != 26:
        raise ToolError("The cipher alphabet must be exactly 26 different letters.")
    src, dst = (alphabet, ALPHA) if dec else (ALPHA, alphabet)
    table = {}
    for a, b in zip(src, dst):
        table[a] = b
        table[a.lower()] = b.lower()
    return "".join(table.get(c, c) for c in text)


tool(id="xor", name="XOR", category=CAT,
     summary="Exclusive-or against a repeating key — the CTF workhorse",
     explain=("XOR every byte with a repeating key. It is its own inverse, so one operation "
              "does both. With a single-byte key it is a Caesar cipher for bytes; with a key "
              "as long as the message and never reused, it is a one-time pad and unbreakable. "
              "Anything in between leaks badly — repeated key material makes the plaintext "
              "recoverable."),
     example="key 'k' — 'hi'  ->  0x03 0x02",
     security="Repeating-key XOR is not encryption. Only a truly random, never-reused, full-length key is secure.",
     tags=["ctf", "one-time pad", "otp", "eor"],
     params=[Param("key", "Key", "text", "key", width=24),
             Param("key_format", "Key is", "choice", "auto",
                   choices=["auto", "text", "hex", "base64", "decimal byte"],
                   help="Auto works it out from the shape of what you typed."),
             Param("in_format", "Input is", "choice", "auto",
                   choices=["auto", "text", "hex", "base64"],
                   help="Auto spots hex and Base64, so un-XORing something you produced "
                        "earlier just works. Set it by hand if it guesses wrong."),
             Param("out_format", "Show result as", "choice", "auto",
                   choices=["auto", "hex", "base64", "text"])],
     encode=lambda d, key="key", key_format="auto", in_format="auto", out_format="auto":
         _xor(d, key, key_format, out_format, in_format),
     decode=lambda d, key="key", key_format="auto", in_format="auto", out_format="auto":
         _xor(d, key, key_format, out_format, in_format),
     encode_label="XOR", decode_label="XOR (same thing)",
     binary_ok=True)


def _xor(data, key, key_format, out_format, in_format="auto"):
    from .core import decode_as
    raw, used_in = decode_as(data, in_format)
    if key_format == "decimal byte":
        try:
            values = [int(t) for t in key.replace(",", " ").split()]
        except ValueError as exc:
            raise ToolError("The key is set to 'decimal byte' but is not a list of "
                            "numbers. Change 'Key is' to text, or type numbers.") from exc
        if any(v < 0 or v > 255 for v in values):
            raise ToolError("Decimal key values have to be between 0 and 255.")
        kb, used_key = bytes(values), "decimal"
    else:
        kb, used_key = decode_as(key, key_format)
    if not kb:
        raise ToolError("XOR needs a key.")
    out = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(raw))
    detected = ""
    if in_format in ("auto", None) or key_format in ("auto", None):
        detected = f"Read the input as {used_in} and the key as {used_key}. "
    if out_format == "hex":
        return Result(text=out.hex(), data=out, note=detected.strip())
    if out_format == "base64":
        import base64 as _b
        return Result(text=_b.b64encode(out).decode(), data=out, note=detected.strip())
    if out_format == "text":
        return Result(text=out.decode("utf-8", errors="replace"), data=out,
                      note=detected.strip())
    try:
        t = out.decode("utf-8")
        if all(c == "\n" or c == "\t" or 32 <= ord(c) < 127 or ord(c) > 160 for c in t):
            return Result(text=t, data=out,
                          note=(detected + "The result is readable text.").strip())
    except UnicodeDecodeError:
        pass
    from .core import pretty_hex
    return Result(text=pretty_hex(out), data=out,
                  note=detected + "The result is not printable text, so it is shown as hex. "
                                  "Use Save to keep the real bytes.")


tool(id="xor-crack", name="XOR key finder", category=CAT,
     summary="Recovers a repeating XOR key from ciphertext alone",
     explain=("Estimates the key length using Hamming distance between blocks, then solves each "
              "key byte by scoring the resulting plaintext against English. This is the "
              "standard attack, and it is the reason repeating-key XOR is not encryption."),
     tags=["crack", "ctf", "hamming", "solve"],
     params=[Param("maxlen", "Longest key to try", "int", 40, minimum=2, maximum=64),
             Param("input_format", "Ciphertext is", "choice", "auto",
                   choices=["auto", "hex", "base64", "raw text/bytes"],
                   help="Auto spots hex and Base64 for you.")],
     action=lambda d, maxlen=40, input_format="auto": _xor_crack(d, int(maxlen), input_format),
     action_label="Find the key",
     binary_ok=True)


def _printable_score(raw: bytes) -> float:
    """How much does this look like English text held in bytes?"""
    return byte_english_score(raw)


def _xor_crack(data, maxlen, input_format):
    from .core import decode_as
    if input_format == "raw text/bytes":
        raw, used = to_bytes(data), "raw bytes"
    else:
        raw, used = decode_as(data, input_format)
    if len(raw) < 4:
        raise ToolError("Need at least 4 bytes of ciphertext.")

    def solve(klen):
        key = bytearray()
        for i in range(klen):
            col = raw[i::klen]
            key.append(max(range(256), key=lambda kb: _printable_score(
                bytes(c ^ kb for c in col))))
        key = bytes(key)
        plain = bytes(c ^ key[i % klen] for i, c in enumerate(raw))
        return key, plain, _printable_score(plain)

    import math
    # Each key byte is a free parameter chosen from 256, so a longer key always
    # fits better. Charging log(256) nats per key byte is what stops the solver
    # running away to a 19-byte key on a 70-byte message.
    penalty = math.log(256) / len(raw)
    maxlen = clamp(maxlen, 1, 64, 40)
    results = []
    for klen in range(1, min(maxlen, max(1, len(raw) // 2)) + 1):
        k, pl, sc = solve(klen)
        results.append((klen, k, pl, sc, sc - klen * penalty))
    klen, key, plain, score, _adj = max(results, key=lambda r: r[4])
    ranked = sorted(results, key=lambda r: r[4], reverse=True)[:8]
    rows = [(r[0], repr(r[1])[2:-1][:32], "%+.3f" % r[4],
             r[2].decode("latin-1")[:60].replace("\n", " "),
             CHOSEN if r[0] == klen else "")
            for r in ranked]
    return Result(text=plain.decode("utf-8", errors="replace"), data=plain, rows=rows,
                  headers=["Key len", "Key", "Score", "Plaintext", ""],
                  note=(f"Read the ciphertext as {used}. " if input_format == "auto" else "")
                       + f"Best key: {key!r} ({klen} byte" + ("s" if klen != 1 else "") + ").")


tool(id="otp", name="One-time pad", category=CAT,
     summary="The only cipher proven unbreakable — and the hardest to use",
     explain=("Add a truly random key, the same length as the message, to the plaintext and "
              "never use that key again. Done properly the ciphertext could decode to any "
              "message of the same length, so there is nothing to attack.\n\n"
              "Every practical failure of the one-time pad comes from breaking one of those "
              "three rules: the key was not random, not as long as the message, or was used "
              "twice. Generate a pad here and keep it somewhere the message never goes."),
     security="Secure only if the pad is truly random, never reused, and shared safely. Reusing a pad destroys it completely.",
     tags=["vernam", "otp", "unbreakable", "pad"],
     params=[Param("pad", "Pad (letters, or leave blank to generate)", "multiline", ""),
             Param("mode", "Work on", "choice", "letters A–Z", choices=["letters A–Z", "bytes (XOR)"])],
     encode=lambda d, pad="", mode="letters A–Z": _otp(to_text(d), pad, mode, False),
     decode=lambda d, pad="", mode="letters A–Z": _otp(to_text(d), pad, mode, True))


def _otp(text, pad, mode, dec):
    import secrets
    if mode.startswith("bytes"):
        raw = to_bytes(text)
        if not pad.strip():
            if dec:
                raise ToolError("Decoding needs the pad that was used.")
            kb = secrets.token_bytes(len(raw))
            out = bytes(a ^ b for a, b in zip(raw, kb))
            return Result(text=out.hex(), data=out,
                          note=f"Generated pad (keep this, you cannot decode without it):\n{kb.hex()}")
        kb = bytes.fromhex("".join(c for c in pad.lower() if c in "0123456789abcdef"))
        if len(kb) < len(raw):
            raise ToolError(f"Pad is {len(kb)} bytes but the message needs {len(raw)}.")
        return Result(data=bytes(a ^ b for a, b in zip(raw, kb)),
                      text=bytes(a ^ b for a, b in zip(raw, kb)).decode("utf-8", errors="replace"))
    letters = strip_non_alpha(text).upper()
    if not pad.strip():
        if dec:
            raise ToolError("Decoding needs the pad that was used.")
        k = "".join(ALPHA[secrets.randbelow(26)] for _ in letters)
        out = "".join(ALPHA[(ord(a) - 65 + ord(b) - 65) % 26] for a, b in zip(letters, k))
        return Result(text=" ".join(out[i:i + 5] for i in range(0, len(out), 5)),
                      note="Generated pad (keep this, you cannot decode without it):\n"
                           + " ".join(k[i:i + 5] for i in range(0, len(k), 5)))
    k = strip_non_alpha(pad).upper()
    if len(k) < len(letters):
        raise ToolError(f"Pad has {len(k)} letters but the message needs {len(letters)}.")
    sign = -1 if dec else 1
    out = "".join(ALPHA[(ord(a) - 65 + sign * (ord(b) - 65)) % 26] for a, b in zip(letters, k))
    return " ".join(out[i:i + 5] for i in range(0, len(out), 5)) if not dec else out
