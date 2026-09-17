"""More classical ciphers - the ones that turn up in puzzles and CTFs.

These sit alongside the main classical set. The common thread is that they all
work on letters and all have a real inverse, so encode then decode with the
same key gives back exactly what went in (allowing for the padding a few of
them need).
"""
from __future__ import annotations

from .core import ALPHA, Param, ToolError, clamp, strip_non_alpha, to_text, tool

CAT = "Classical ciphers"


# --------------------------------------------------------------------------
# Porta - reciprocal, so one operation does both ways
# --------------------------------------------------------------------------

def _porta(text, key, dec):
    key = strip_non_alpha(key).upper() or "KEY"
    letters = strip_non_alpha(text).upper()
    out = []
    for i, c in enumerate(letters):
        k = ord(key[i % len(key)]) - 65
        row = k // 2
        p = ord(c) - 65
        if p < 13:
            r = (p + row) % 13 + 13
        else:
            r = (p - 13 - row) % 13
        out.append(chr(r + 65))
    return "".join(out)


tool(id="porta", name="Porta cipher", category=CAT,
     summary="Reciprocal polyalphabetic cipher - the same step encrypts and decrypts",
     explain=(
         "A 16th-century polyalphabetic cipher with one neat property: it is its own inverse. "
         "Each pair of key letters (A and B share a row, C and D the next, and so on) picks "
         "one of thirteen reciprocal alphabets that swap the top and bottom halves of the "
         "alphabet. Because the swap is symmetric, running the ciphertext through with the "
         "same key gives the plaintext back - there is no separate decrypt.\n\n"
         "Harder than Vigenère to break by hand because a letter never maps to itself and the "
         "two halves are always exchanged."),
     example="key: FORTIFICATION",
     tags=["porta", "polyalphabetic", "reciprocal", "classical"],
     params=[Param("key", "Key", "text", "FORTIFICATION", width=20)],
     encode=lambda d, key="FORTIFICATION": _porta(d, key, False),
     decode=lambda d, key="FORTIFICATION": _porta(d, key, True))


# --------------------------------------------------------------------------
# Gronsfeld - Vigenere with a number key
# --------------------------------------------------------------------------

def _gronsfeld(text, key, dec):
    digits = [int(c) for c in str(key) if c.isdigit()]
    if not digits:
        raise ToolError("Gronsfeld needs a numeric key, e.g. 31415.")
    out, j = [], 0
    for c in to_text(text):
        if "a" <= c <= "z" or "A" <= c <= "Z":    # isalpha() is true for é, Ω ...
            base = 65 if c.isupper() else 97
            shift = digits[j % len(digits)]
            shift = -shift if dec else shift
            out.append(chr((ord(c) - base + shift) % 26 + base))
            j += 1
        else:
            out.append(c)
    return "".join(out)


tool(id="gronsfeld", name="Gronsfeld cipher", category=CAT,
     summary="Vigenère driven by a number instead of a keyword",
     explain=(
         "Gronsfeld is Vigenère with a numeric key: each digit shifts the corresponding "
         "letter by that many places. A key of 31415 shifts the first letter by 3, the next "
         "by 1, then 4, 1, 5, and repeats.\n\n"
         "Because the key only uses shifts 0-9 rather than the full 0-25, it is weaker than "
         "Vigenère and shows up mostly in puzzles - but it is the natural cipher to reach for "
         "when the key you have been given is a number."),
     example="key: 31415",
     tags=["gronsfeld", "vigenere", "numeric", "classical"],
     params=[Param("key", "Number key", "text", "31415", width=16)],
     encode=lambda d, key="31415": _gronsfeld(d, key, False),
     decode=lambda d, key="31415": _gronsfeld(d, key, True))


# --------------------------------------------------------------------------
# Polybius-based fractionation: Bifid, Trifid, Nihilist, Four-square
# --------------------------------------------------------------------------

def _square5(key):
    seen, sq = [], []
    for c in (strip_non_alpha(key).upper().replace("J", "I") + ALPHA.replace("J", "")):
        if c not in seen and c != "J":
            seen.append(c)
    return "".join(seen)   # 25 letters


def _bifid(text, key, period, dec):
    sq = _square5(key)
    pos = {c: (i // 5, i % 5) for i, c in enumerate(sq)}
    letters = [c for c in strip_non_alpha(text).upper().replace("J", "I") if c in pos]
    if not letters:
        return ""
    period = int(clamp(period, 0, 100, 5)) or len(letters)
    out = []
    for i in range(0, len(letters), period):
        block = letters[i:i + period]
        rows = [pos[c][0] for c in block]
        cols = [pos[c][1] for c in block]
        if not dec:
            seq = rows + cols
            out += [sq[seq[2 * j] * 5 + seq[2 * j + 1]] for j in range(len(block))]
        else:
            nums = []
            for c in block:
                nums += [pos[c][0], pos[c][1]]
            half = len(nums) // 2
            r, cc = nums[:half], nums[half:]
            out += [sq[r[j] * 5 + cc[j]] for j in range(len(block))]
    return "".join(out)


tool(id="bifid", name="Bifid cipher", category=CAT,
     summary="Delastelle's fractionating cipher on a 5×5 keyed square",
     explain=(
         "Bifid splits each letter into its row and column on a keyed 5×5 square, then "
         "recombines those coordinates across a block before turning them back into letters. "
         "The effect is that each output letter depends on two input letters, which smears "
         "the statistics and defeats simple frequency analysis.\n\n"
         "The period is the block length the coordinates are mixed over - a bigger period "
         "spreads the diffusion further. J is merged into I, as on the classic square."),
     example="key: CIPHER, period: 5",
     tags=["bifid", "delastelle", "fractionation", "polybius", "classical"],
     params=[Param("key", "Square key", "text", "CIPHER", width=18),
             Param("period", "Period", "int", 5, minimum=0, maximum=100,
                   help="Block length coordinates mix over. 0 = the whole message.")],
     encode=lambda d, key="CIPHER", period=5: _bifid(d, key, period, False),
     decode=lambda d, key="CIPHER", period=5: _bifid(d, key, period, True))


_TRI = ALPHA + "."


def _cube(key):
    seen = []
    for c in (strip_non_alpha(key).upper() + _TRI):
        if c in _TRI and c not in seen:
            seen.append(c)
    return "".join(seen)   # 27 symbols


def _trifid(text, key, period, dec):
    cube = _cube(key)
    pos = {c: (i // 9, (i // 3) % 3, i % 3) for i, c in enumerate(cube)}
    src = to_text(text).upper()
    letters = [c for c in src if c in pos] or [c for c in src.replace(" ", "") if c in pos]
    if not letters:
        return ""
    period = int(clamp(period, 0, 100, 5)) or len(letters)
    out = []
    for i in range(0, len(letters), period):
        block = letters[i:i + period]
        if not dec:
            trip = [[], [], []]
            for c in block:
                a, b, cc = pos[c]
                trip[0].append(a); trip[1].append(b); trip[2].append(cc)
            seq = trip[0] + trip[1] + trip[2]
            for j in range(len(block)):
                out.append(cube[seq[3 * j] * 9 + seq[3 * j + 1] * 3 + seq[3 * j + 2]])
        else:
            nums = []
            for c in block:
                a, b, cc = pos[c]
                nums += [a, b, cc]
            third = len(nums) // 3
            r0, r1, r2 = nums[:third], nums[third:2 * third], nums[2 * third:]
            for j in range(len(block)):
                out.append(cube[r0[j] * 9 + r1[j] * 3 + r2[j]])
    return "".join(out)


tool(id="trifid", name="Trifid cipher", category=CAT,
     summary="Bifid taken into three dimensions - a 3×3×3 keyed cube",
     explain=(
         "Trifid is Bifid with an extra dimension. Each letter becomes three coordinates on a "
         "keyed 3×3×3 cube of 27 symbols (the alphabet plus a full stop), the three streams "
         "are mixed across a block, and the result is read back as letters. Every output "
         "letter now depends on three input letters, so it diffuses even harder than Bifid.\n\n"
         "Invented by Delastelle around 1900 and, at the time, genuinely strong for a "
         "pencil-and-paper cipher."),
     example="key: CRYPTO, period: 5",
     tags=["trifid", "delastelle", "fractionation", "cube", "classical"],
     params=[Param("key", "Cube key", "text", "CRYPTO", width=18),
             Param("period", "Period", "int", 5, minimum=0, maximum=100)],
     encode=lambda d, key="CRYPTO", period=5: _trifid(d, key, period, False),
     decode=lambda d, key="CRYPTO", period=5: _trifid(d, key, period, True))


def _four_square(text, key1, key2, dec):
    plain = ALPHA.replace("J", "")
    a, b = _square5(key1), _square5(key2)
    letters = [c for c in strip_non_alpha(text).upper().replace("J", "I")]
    if len(letters) % 2:
        letters.append("X")
    pos_p = {c: (i // 5, i % 5) for i, c in enumerate(plain)}
    out = []
    if not dec:
        for i in range(0, len(letters), 2):
            (r1, c1), (r2, c2) = pos_p[letters[i]], pos_p[letters[i + 1]]
            out.append(a[r1 * 5 + c2])
            out.append(b[r2 * 5 + c1])
    else:
        pos_a = {c: (i // 5, i % 5) for i, c in enumerate(a)}
        pos_b = {c: (i // 5, i % 5) for i, c in enumerate(b)}
        for i in range(0, len(letters), 2):
            (r1, c1), (r2, c2) = pos_a[letters[i]], pos_b[letters[i + 1]]
            out.append(plain[r1 * 5 + c2])
            out.append(plain[r2 * 5 + c1])
    return "".join(out)


tool(id="four-square", name="Four-square cipher", category=CAT,
     summary="Encrypts letter pairs across two keyed squares - stronger than Playfair",
     explain=(
         "Four-square encrypts pairs of letters using four 5×5 squares: two plain squares in "
         "the corners and two keyed squares (the two keys you give) on the diagonal. Find the "
         "first letter in the top-left plain square and the second in the bottom-right, then "
         "read the two corners of the rectangle they form out of the keyed squares.\n\n"
         "It fixes Playfair's biggest tell - there is no need to break up double letters, and "
         "the two independent keys make it markedly harder to break. J is merged into I."),
     example="keys: EXAMPLE and KEYWORD",
     tags=["four-square", "digraph", "playfair", "classical"],
     params=[Param("key1", "Top-right key", "text", "EXAMPLE", width=16),
             Param("key2", "Bottom-left key", "text", "KEYWORD", width=16)],
     encode=lambda d, key1="EXAMPLE", key2="KEYWORD": _four_square(d, key1, key2, False),
     decode=lambda d, key1="EXAMPLE", key2="KEYWORD": _four_square(d, key1, key2, True))


def _nihilist(text, key, square_key, dec):
    sq = _square5(square_key)
    pos = {c: (i // 5 + 1) * 10 + (i % 5 + 1) for i, c in enumerate(sq)}
    kletters = [c for c in strip_non_alpha(key).upper().replace("J", "I") if c in pos]
    if not kletters:
        raise ToolError("Nihilist needs a keyword made of letters.")
    knums = [pos[c] for c in kletters]
    if not dec:
        letters = [c for c in strip_non_alpha(text).upper().replace("J", "I") if c in pos]
        nums = [pos[c] + knums[i % len(knums)] for i, c in enumerate(letters)]
        return " ".join(str(n) for n in nums)
    else:
        toks = [int(t) for t in to_text(text).split() if t.strip().isdigit()]
        rev = {v: k for k, v in pos.items()}
        out = []
        for i, n in enumerate(toks):
            v = n - knums[i % len(knums)]
            out.append(rev.get(v, "?"))
        return "".join(out)


tool(id="nihilist", name="Nihilist cipher", category=CAT,
     summary="Polybius numbers plus a repeating numeric key - as used by 1880s revolutionaries",
     explain=(
         "Each letter becomes a two-digit number from a keyed Polybius square (row then "
         "column, counting from 1). Then a keyword - turned into numbers the same way - is "
         "added on top, repeating across the message. The result is a string of numbers, "
         "usually two or three digits each.\n\n"
         "Used by Russian Nihilists against the Tsarist police in the 1880s, and the direct "
         "ancestor of the Soviet VIC cipher. Encode gives numbers; decode takes them back."),
     example="square key: RUSSIAN, keyword: MOSCOW",
     tags=["nihilist", "polybius", "additive", "numeric", "classical", "vic"],
     params=[Param("square_key", "Square key", "text", "RUSSIAN", width=16),
             Param("key", "Additive keyword", "text", "MOSCOW", width=16)],
     encode=lambda d, key="MOSCOW", square_key="RUSSIAN": _nihilist(d, key, square_key, False),
     decode=lambda d, key="MOSCOW", square_key="RUSSIAN": _nihilist(d, key, square_key, True))


# --------------------------------------------------------------------------
# Hill cipher - linear algebra mod 26
# --------------------------------------------------------------------------

def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _modinv(a, m=26):
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        return None
    return x % m


def _parse_matrix(key):
    nums = [int(n) for n in __import__("re").findall(r"-?\d+", key)] if any(
        ch.isdigit() for ch in key) else [ord(c) - 65 for c in strip_non_alpha(key).upper()]
    n = int(round(len(nums) ** 0.5))
    if n * n != len(nums) or n < 2:
        raise ToolError("The Hill key must be a perfect square of numbers (4 for a 2×2, "
                        "9 for a 3×3) or a keyword of the same length, e.g. 'GYBNQKURP'.")
    return [nums[i * n:(i + 1) * n] for i in range(n)], n


def _mat_det(m, n):
    if n == 1:
        return m[0][0]
    if n == 2:
        return m[0][0] * m[1][1] - m[0][1] * m[1][0]
    det = 0
    for c in range(n):
        minor = [[m[i][j] for j in range(n) if j != c] for i in range(1, n)]
        det += ((-1) ** c) * m[0][c] * _mat_det(minor, n - 1)
    return det


def _mat_inv_mod(m, n, mod=26):
    det = _mat_det(m, n) % mod
    di = _modinv(det, mod)
    if di is None:
        raise ToolError(f"This key cannot be used - its determinant ({det}) shares a factor "
                        "with 26, so there is no inverse and it could never be decrypted. "
                        "Pick another key.")
    # cofactor / adjugate
    adj = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            minor = [[m[r][c] for c in range(n) if c != j] for r in range(n) if r != i]
            cof = ((-1) ** (i + j)) * (_mat_det(minor, n - 1) if n > 1 else 1)
            adj[j][i] = (cof * di) % mod
    return adj


def _hill(text, key, dec):
    m, n = _parse_matrix(key)
    if dec:
        m = _mat_inv_mod(m, n)
    else:
        _mat_inv_mod(m, n)   # validate it is invertible so encrypt won't strand you
    letters = [ord(c) - 65 for c in strip_non_alpha(text).upper()]
    while len(letters) % n:
        letters.append(ord("X") - 65)
    out = []
    for i in range(0, len(letters), n):
        block = letters[i:i + n]
        for row in m:
            out.append(chr(sum(row[k] * block[k] for k in range(n)) % 26 + 65))
    return "".join(out)


tool(id="hill", name="Hill cipher", category=CAT,
     summary="Matrix multiplication mod 26 - the first cipher on real linear algebra",
     explain=(
         "The Hill cipher, from 1929, was the first to treat a block of letters as a vector "
         "and multiply it by a key matrix, all arithmetic done modulo 26. A 2×2 key encrypts "
         "letters in pairs, a 3×3 in threes.\n\n"
         "Give the key as numbers (4 of them for a 2×2, 9 for a 3×3) or as a keyword of that "
         "length, which is turned into numbers A=0…Z=25. Not every matrix works: the key has "
         "to be invertible modulo 26 or it could never be decrypted, and Cryptex checks this "
         "and tells you rather than letting you encrypt something you can never get back.\n\n"
         "The message is padded with X to a whole number of blocks."),
     example="key: GYBNQKURP  (a 3×3), or 3,3,2,5",
     tags=["hill", "matrix", "linear algebra", "block", "classical"],
     params=[Param("key", "Key matrix", "text", "GYBNQKURP", width=20,
                   help="Numbers (4 or 9 of them) or a keyword of that length.")],
     encode=lambda d, key="GYBNQKURP": _hill(d, key, False),
     decode=lambda d, key="GYBNQKURP": _hill(d, key, True))


# --------------------------------------------------------------------------
# Fractionated Morse
# --------------------------------------------------------------------------

def _frac_morse(text, key, dec):
    from .encodings import MORSE, MORSE_REV
    # 26 combinations of . - x taken 3 at a time, minus xxx
    syms = ["".join(t) for t in __import__("itertools").product(".-x", repeat=3)]
    syms = [s for s in syms if s != "xxx"][:26]
    kalpha = []
    for c in (strip_non_alpha(key).upper() + ALPHA):
        if c not in kalpha:
            kalpha.append(c)
    table = dict(zip(syms, kalpha))
    rev = {v: k for k, v in table.items()}

    if not dec:
        morse = []
        for c in to_text(text).upper():
            if c == " ":
                continue
            m = MORSE.get(c)
            if m:
                morse.append(m)
        stream = "x".join(morse) + "xx"
        stream = stream.replace("-", "-")  # already dots/dashes
        while len(stream) % 3:
            stream += "x"
        out = [table[g] for i in range(0, len(stream), 3)
               for g in [stream[i:i + 3]] if g != "xxx"]
        return "".join(out)
    else:
        letters = strip_non_alpha(text).upper()
        stream = "".join(rev.get(c, "") for c in letters)
        tokens = stream.split("x")
        out = []
        for t in tokens:
            if t == "":
                continue
            out.append(MORSE_REV.get(t, ""))
        return "".join(out)


tool(id="fractionated-morse", name="Fractionated Morse", category=CAT,
     summary="Morse turned into groups of three, then substituted - a WWII field cipher",
     explain=(
         "The message is written in Morse with an 'x' between letters, then that stream of "
         "dots, dashes and x's is chopped into groups of three. There are 26 possible groups "
         "(dropping the all-x one), so each maps to a letter of a keyed alphabet.\n\n"
         "Because the letter boundaries disappear into the Morse before it is re-cut into "
         "threes, the same plaintext letter comes out differently depending on its "
         "neighbours - which is what makes it much harder than a plain substitution. Used as "
         "a field cipher in the Second World War."),
     example="key: CIPHER",
     tags=["fractionated morse", "morse", "wwii", "substitution", "classical"],
     params=[Param("key", "Keyed alphabet", "text", "CIPHER", width=18)],
     encode=lambda d, key="CIPHER": _frac_morse(d, key, False),
     decode=lambda d, key="CIPHER": _frac_morse(d, key, True))
