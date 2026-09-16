"""How much does this look like something a person wrote?

Everything that ranks candidates - the Caesar brute forcer, the Vigenere and
XOR solvers, and above all the auto-solver - needs one honest answer to that
question. Keeping it in one place means they all agree, and improving it
improves all of them at once.
"""
from __future__ import annotations

import math
import re

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# The 350 or so commonest English words. Enough that ordinary prose scores
# clearly above cipher text, small enough to keep in the source.
COMMON_WORDS = {w.upper() for w in """
the be to of and a in that have i it for not on with he as you do at this but his
by from they we say her she or an will my one all would there their what so up out
if about who get which go me when make can like time no just him know take people
into year your good some could them see other than then now look only come its over
think also back after use two how our work first well way even new want because any
these give day most us is was are were been has had did does done said made went
came got left right big small long short high low old young new great little own
other same last next early late able bad best better free full low main only public
real right sure whole young man men woman women child children people person life
world year day time week month night morning today tomorrow yesterday hand eye head
face body water fire air earth house home room door window road street city town
country place name word letter number line page book paper story news message
mother father brother sister family friend king queen lord god war peace army
soldier enemy attack defend secret code key cipher message send receive meet dawn
dusk north south east west here there where why how what who when which
quick brown fox jump lazy dog over under above below between through across
around before during without within among against toward behind beside near far
discover discovered find found lost keep kept hold held bring brought take took
give gave send sent receive return tell told ask asked answer call called speak
spoke talk walk walked run ran move moved turn turned open opened close closed
start started stop stopped begin began end ended follow followed lead led
carry carried build built break broke cut put set let put show shown seem seemed
feel felt leave leaving learn learned change changed play played help helped
live lived believe believe write written read reading hear heard watch watched
buy bought pay paid sell sold meet met wait waited stand stood sit sat lie lay
remember forget forgot understand understood mean meant matter matters happen
happened continue continued remain remained appear appeared become became
number numbers money price cost value point points part parts side sides top
bottom front back middle inside outside above beyond across along until since
though although however therefore because before after while unless whether
always never often sometimes usually rarely again once twice already still yet
almost enough quite rather very really much many few several every each both
either neither none nothing something anything everything someone anyone
everyone nobody somewhere anywhere everywhere perhaps maybe certainly surely
information system service company business project report plan planning data
file files record records office team member members group member support
question questions problem problems answer solution result results reason
example order orders case cases level levels area areas field power control
board list table chart image picture sound voice music light dark colour color
green blue black white grey gray yellow purple orange brown silver gold
morning afternoon evening midnight hour minute second january february march
april may june july august september october november december monday tuesday
wednesday thursday friday saturday sunday
""".split()}

# Percentage of all English letter pairs. A bigram model separates English from
# near-English far better than counting single letters.
_BIGRAM_RAW = (
    "TH3.56 HE3.07 IN2.43 ER2.05 AN1.99 RE1.85 ON1.76 AT1.49 EN1.45 ND1.35 "
    "TI1.34 ES1.34 OR1.28 TE1.20 OF1.17 ED1.17 IS1.13 IT1.12 AL1.09 AR1.07 "
    "ST1.05 TO1.05 NT1.04 NG0.95 SE0.93 HA0.93 AS0.87 OU0.87 IO0.83 LE0.83 "
    "VE0.83 CO0.79 ME0.79 DE0.76 HI0.76 RI0.73 RO0.73 IC0.70 NE0.69 EA0.69 "
    "RA0.69 CE0.65 LI0.62 CH0.60 LL0.58 BE0.58 MA0.57 SI0.55 OM0.55 UR0.54 "
    "CA0.54 EL0.53 TA0.53 LA0.53 NS0.51 DI0.50 FO0.50 HO0.46 PE0.46 EC0.45 "
    "PR0.45 NO0.45 CT0.44 US0.44 AC0.44 IL0.43 OT0.42 NA0.42 UT0.42 IV0.41 "
    "WI0.40 WH0.40 SO0.40 MO0.39 AD0.38 SS0.38 WE0.37 EM0.37 UN0.37 SU0.37 "
    "EV0.36 PA0.36 ID0.36 FI0.36 GE0.35 LO0.35 TR0.35 IM0.34 AI0.33 PO0.33 "
    "RT0.33 AM0.33 LY0.31 OL0.31 EE0.30 DA0.30 GH0.30 AB0.30 MI0.30 EP0.29 "
    "AG0.29 HT0.29 SA0.29 IR0.29 SH0.28 EI0.27 CI0.27 SC0.26 RS0.26 IG0.26 "
    "PL0.25 OW0.25 UL0.25 TU0.25 FE0.25 OS0.25 AP0.25 BL0.24 AY0.24 DO0.24 "
    "OP0.24 EF0.23 NC0.23 RD0.23 IE0.23 UC0.22 OO0.22 AV0.22 BU0.22 YS0.22 "
    "PP0.21 EX0.21 SP0.21 GR0.21 RC0.21 CL0.20 "
    # The tail matters more than it looks: without it, perfectly good
    # plaintext with a CK or a QU in it gets punished as if it were noise.
    "CK0.19 KE0.20 GO0.24 WA0.17 LD0.16 AW0.16 FR0.16 CR0.15 DR0.15 BA0.14 "
    "BO0.13 TT0.12 GI0.12 YO0.12 WO0.12 VI0.11 BR0.11 FA0.11 TS0.11 YE0.11 "
    "OV0.10 QU0.10 LT0.10 KI0.10 RR0.10 HU0.10 UD0.09 IP0.09 OD0.09 OC0.09 "
    "MP0.09 NN0.09 IA0.09 IF0.09 PI0.09 BI0.09 PS0.09 WN0.09 EW0.09 VA0.09 "
    "LS0.08 AF0.08 RY0.08 GT0.08 EY0.07 OB0.07 UP0.07 RU0.07 AU0.07 DD0.07 "
    "FF0.07 PU0.07 TW0.07 GU0.06 SK0.06 LU0.06 UM0.06 UG0.06 MU0.06 RM0.06 "
    "RN0.06 DS0.06 CU0.06 AK0.06 OG0.06 FT0.06 SL0.06 EO0.06 HR0.06 SW0.06 "
    "GL0.05 NF0.05 IB0.05 UB0.05 UE0.05 MS0.05 RK0.05 NK0.05 FL0.05 FU0.05 "
    "DU0.05 PT0.05 BY0.05 YA0.05 VO0.05 EG0.05 CC0.05 GA0.19 TL0.04 OI0.04 "
    "OK0.04 MB0.04 MM0.04 RG0.04 NV0.04 JU0.04 XP0.04 YT0.04 SY0.03 NY0.03 "
    "NU0.03 LV0.03 RV0.03 RB0.03 RL0.03 HY0.03 WR0.03 WS0.03 YI0.03 YL0.03 "
    "YM0.03 YR0.03 OY0.03 UA0.03 UI0.03 IK0.03 EB0.03 EU0.03 DY0.03 GG0.03 "
    "KN0.03 LF0.03 LK0.03 LM0.03 LP0.03 TC0.03 XT0.03 MY0.03 JO0.03 "
    "NB0.02 NL0.02 NM0.02 NP0.02 NR0.02 NW0.02 LB0.02 LC0.02 RF0.02 RH0.02 "
    "RP0.02 SB0.02 SD0.02 SF0.02 DL0.02 DM0.02 DN0.02 DW0.02 DT0.02 TM0.02 "
    "YB0.02 YC0.02 YD0.02 YN0.02 YP0.02 YW0.02 ZE0.02 JE0.02 JA0.02 XC0.02 "
    "XI0.02 XE0.02 PY0.02 BS0.02 EQ0.02 EH0.02 EK0.02 OE0.02 HB0.02 CY0.02 "
    "AX0.01 AZ0.01 AH0.02 AJ0.01 AQ0.01 IQ0.01 IU0.01 IX0.01 IZ0.01 OX0.01 "
    "OZ0.01 OJ0.01 UF0.01 UK0.01 UO0.01 UV0.01 UY0.01 YF0.01 YG0.01 YH0.01 "
    "ZA0.01 ZI0.01 ZO0.01 JI0.01 VU0.01 WL0.01 WD0.01 XA0.01 PM0.01 PN0.01 "
    "PH0.04 BT0.01 FY0.01 TN0.01 TF0.01 TP0.01 RW0.01 SG0.01 LG0.01 LN0.01 "
    "LR0.01 LW0.01 CS0.01 MN0.01 MF0.01 MD0.01 HL0.01 HN0.01 HM0.01 HW0.01 "
    "SM0.05 SN0.04 SQ0.01 GN0.03 NH0.02 NJ0.01 NZ0.01 UQ0.01 UX0.01 OQ0.01"
)
BIGRAM_PCT = {t[:2]: float(t[2:]) for t in _BIGRAM_RAW.split()}
_REST = max(0.001, (100.0 - sum(BIGRAM_PCT.values())) / (676 - len(BIGRAM_PCT)))

ENGLISH_FREQ = {
    'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70, 'F': 2.23,
    'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03,
    'M': 2.41, 'N': 6.75, 'O': 7.51, 'P': 1.93, 'Q': 0.10, 'R': 5.99,
    'S': 6.33, 'T': 9.06, 'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15,
    'Y': 1.97, 'Z': 0.07,
}

# Byte-level model, for the single-byte and repeating-key XOR solvers. Space is
# the commonest character in English and is what actually gives a key away.
_BYTE_FREQ = {
    32: 18.00, 101: 10.20, 116: 7.51, 97: 6.53, 111: 6.16, 110: 5.71,
    105: 5.67, 115: 5.32, 114: 4.99, 104: 4.98, 108: 3.25, 100: 3.28,
    99: 2.23, 117: 2.27, 109: 2.03, 102: 1.98, 119: 1.70, 103: 1.63,
    112: 1.50, 121: 1.43, 98: 1.26, 118: 0.80, 107: 0.56, 120: 0.14,
    106: 0.10, 113: 0.09, 122: 0.05, 46: 0.65, 44: 0.61, 39: 0.24,
    34: 0.15, 45: 0.15, 58: 0.10, 59: 0.05, 63: 0.08, 33: 0.08,
    10: 0.50, 13: 0.10, 9: 0.05,
}
for _d in range(48, 58):
    _BYTE_FREQ[_d] = 0.25
for _u in range(65, 91):
    _BYTE_FREQ[_u] = _BYTE_FREQ.get(_u + 32, 0.5) * 0.12


def byte_english_score(raw: bytes) -> float:
    """Mean log-likelihood that these bytes are English text. Higher is better."""
    if not raw:
        return -1e9
    total = 0.0
    for b in raw:
        pct = _BYTE_FREQ.get(b)
        if pct is None:
            pct = 0.02 if 32 <= b < 127 else 0.0005
        total += math.log(pct / 100.0)
    return total / len(raw)


def letter_loglik(text: str) -> float:
    """Mean log-likelihood of the letters under an English bigram model."""
    letters = "".join(c for c in text.upper() if c in ALPHA)
    if len(letters) < 2:
        return -1e9
    total = 0.0
    for i in range(len(letters) - 1):
        total += math.log(BIGRAM_PCT.get(letters[i:i + 2], _REST) / 100.0)
    return total / (len(letters) - 1)


def chi_english(letters: str) -> float:
    """Chi-squared fit to English letter frequencies. Higher (less negative) is better."""
    letters = [c for c in letters.upper() if c in ALPHA]
    if not letters:
        return -1e9
    n = len(letters)
    chi = 0.0
    for c in ALPHA:
        exp = ENGLISH_FREQ[c] * n / 100.0
        chi += (letters.count(c) - exp) ** 2 / max(exp, 0.5)
    return -chi / n


def index_of_coincidence(letters) -> float:
    n = len(letters)
    if n < 2:
        return 0.0
    counts = {c: letters.count(c) for c in set(letters)}
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


_SEG_WORDS = {w for w in COMMON_WORDS if len(w) >= 3}
_SEG_SHORT = {w for w in COMMON_WORDS if len(w) == 2}
_SEG_MAX = max((len(w) for w in COMMON_WORDS), default=3)


def segment_coverage(text: str) -> float:
    """Share of the letters that can be read as common English words when the
    spaces are missing - which is how a solved classical cipher arrives.

    ATTACKATDAWNBRINGTHEMAPS splits cleanly into real words; a random string
    of the same letters does not. Two-letter words count for half, because
    enough of them turn up by chance to be worth discounting.
    """
    letters = "".join(c for c in text.upper() if c.isalpha())
    n = len(letters)
    if n < 6 or n > 4000:
        return 0.0
    best = [0.0] * (n + 1)
    for i in range(1, n + 1):
        best[i] = best[i - 1]
        for length in range(2, min(_SEG_MAX, i) + 1):
            piece = letters[i - length:i]
            if length == 2:
                if piece in _SEG_SHORT:
                    best[i] = max(best[i], best[i - length] + length * 0.5)
            elif piece in _SEG_WORDS:
                best[i] = max(best[i], best[i - length] + length)
    return min(1.0, best[n] / n)


def word_coverage(text: str) -> float:
    """Share of the LETTERS that sit inside common English words.

    Counting whole words instead lets a scatter of two-letter accidents - IT,
    AT, ON - carry a line of nonsense to a respectable score. Counting letters
    makes long real words count for what they are worth, and short accidental
    ones count for very little.
    """
    words = re.findall(r"[A-Za-z']{1,}", text)
    if not words:
        return 0.0
    total = sum(len(w) for w in words)
    if not total:
        return 0.0
    hit = 0
    for w in words:
        if len(w) >= 3 and w.upper() in COMMON_WORDS:
            hit += len(w)
        elif len(w) == 2 and w.upper() in COMMON_WORDS:
            hit += 1
    return hit / total


_STRUCTURE = (
    (re.compile(r"^\s*<\?xml", re.I), "XML"),
    (re.compile(r"^\s*<(!doctype html|html)\b", re.I), "HTML"),
    (re.compile(r"-----BEGIN [A-Z0-9 ]+-----"), "a PEM block"),
    (re.compile(r"^\s*https?://\S+\s*$", re.I), "a URL"),
    (re.compile(r"^[\w.+-]+@[\w-]+\.[\w.]+$"), "an email address"),
    (re.compile(r"^\s*(flag|ctf|key)\{.*\}\s*$", re.I), "a CTF flag"),
)


def structure_hint(text: str):
    """Recognisable shapes that count as 'solved' even without English words.

    JSON is checked by actually parsing it. Matching brackets alone is not
    nearly enough - plenty of cipher output starts with [ and ends with ],
    and treating that as a solved puzzle sends the whole search off a cliff.
    """
    head = text.strip()[:1]
    if head in "[{" and len(text) < 400_000:
        import json
        try:
            parsed = json.loads(text)
            if isinstance(parsed, (dict, list)) and parsed:
                return "JSON"
        except Exception:
            pass
    for pattern, name in _STRUCTURE:
        if pattern.search(text[:4000]):
            return name
    return None


def readability(value) -> float:
    """0 to 1: how much this looks like a finished, readable answer.

    This is the number the auto-solver ranks everything by, so it has to be
    hard to fool. A run of letters that merely has English-ish frequencies
    scores moderately; actual words, or a recognisable structure, score high.
    """
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
            return 0.05 * (printable / len(raw)) if raw else 0.0
    else:
        text = str(value)
        raw = text.encode("utf-8", errors="replace")
    if not text.strip():
        return 0.0

    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    printable_ratio = printable / len(text)
    if printable_ratio < 0.85:
        return 0.05 * printable_ratio

    if structure_hint(text):
        return 0.97

    letters = sum(1 for c in text if c.isalpha())
    letter_ratio = letters / len(text)

    bigram = letter_loglik(text)
    bigram_norm = 0.0 if bigram < -100 else max(0.0, min(1.0, (bigram + 3.55) / 1.05))
    spaces = text.count(" ") / max(1, len(text))

    if spaces >= 0.03:
        words = min(1.0, word_coverage(text) / 0.55)
    else:
        # No spaces: fall back to reading the letters as run-together words
        words = min(1.0, segment_coverage(text) / 0.85)

    # Three signals: whole words, letter pairs, and four-letter runs. The
    # quadgram term is what separates a nearly-right key from a right one.
    quad = fitness(text) if letters > 12 else 0.0
    score = 0.52 * words + 0.20 * bigram_norm + 0.18 * quad + 0.10 * printable_ratio
    if letter_ratio < 0.35:                     # mostly digits or symbols
        score *= 0.45 + 0.55 * letter_ratio
    if 0.08 <= spaces <= 0.25:                  # about the right density of gaps
        score = min(1.0, score + 0.06)
    return max(0.0, min(1.0, score))


def describe(value) -> str:
    """A short human label for what a candidate result appears to be."""
    text = value.decode("utf-8", "replace") if isinstance(value, (bytes, bytearray)) else str(value)
    hint = structure_hint(text)
    if hint:
        return hint
    if word_coverage(text) >= 0.50:
        return "English text"
    seg = segment_coverage(text)
    if seg >= 0.80:
        return "English words, no spaces"
    if word_coverage(text) >= 0.28 or seg >= 0.55:
        return "possibly English"
    if letter_loglik(text) > -3.05:
        return "English-shaped letters"
    return "not obviously readable"


# --------------------------------------------------------------------------
# Quadgram fitness
# --------------------------------------------------------------------------
#
# Four-letter statistics are what actually break a substitution cipher: pairs
# of letters are too weak to tell a nearly-right key from a right one.
#
# The usual quadgram table is a few hundred thousand lines scraped from a
# corpus, which is not something to paste into a source file. Instead the model
# is BUILT at first use from the word list above, weighted so the common words
# dominate, with a fixed seed so it is identical on every machine and every
# run. It captures the within-word structure that matters, plus the letter
# pairs that straddle a space, and it costs about a tenth of a second once.

_QUAD = None
_QUAD_FLOOR = 0.0
_QUAD_TOTAL = 0

# Weighted so "the", "of" and "and" carry the load they carry in real English
_HEAVY = """the of and to a in is that it for was on with as be at by this have
from or had not but what all were when we there can an your which their said if
do will each about how up out them then she many some so these would other into
has more her two like him see time could no make than first been its who now
people my over know water only new very after just where most know through back
much before go good our any day same right look think also around another came
come work three word must because does part even place well such here take why
things help put years different away again off went old number great tell men
say small every found still between name should home big give air line set own
under read last never us left end along while might next sound below saw
something thought both few those always looked show large often together asked
house don world going want school important until form food keep children feet
land side without boy once animal life enough took sometimes four head above
kind began almost live page got earth need far hand high year mother light
country father let night picture being study second soon story since white ever
paper hard near sentence better best across during today however sure means
knew try told young miles sun ways thing whole hear example heard several change
answer room against top turned learn point city play toward five himself usually
money seen didn car morning I'm body upon family later turn move face door cut
done group true half red fish plants living black eat short united run book
gave order open ground cold really table remember tree course front American
space inside ago sad early I'll learned brought close nothing though idea before
lost basic whether attack secret message dawn bring maps men money mill tonight
"""


def _build_quadgrams():
    """Deterministic pseudo-corpus, then count every four-letter run in it."""
    import random
    words = [w.upper() for w in _HEAVY.split() if w.isalpha()]
    extra = sorted(COMMON_WORDS - set(words))
    # the heavy list is roughly frequency-ordered, so rank-weight it
    weights = [max(1.0, 240.0 / (i + 1)) for i in range(len(words))]
    words += extra
    weights += [0.6] * len(extra)
    rng = random.Random(20260914)
    corpus = " ".join(rng.choices(words, weights=weights, k=42000))
    counts = {}
    letters = corpus.replace(" ", "")
    # within words, where the real structure is
    for i in range(len(letters) - 3):
        q = letters[i:i + 4]
        counts[q] = counts.get(q, 0) + 1
    # and across the gaps, so word boundaries are represented too
    squeezed = corpus
    for i in range(len(squeezed) - 4):
        chunk = squeezed[i:i + 5].replace(" ", "")
        if len(chunk) == 4:
            counts[chunk] = counts.get(chunk, 0) + 1
    total = sum(counts.values())
    return counts, total


def _quad():
    global _QUAD, _QUAD_TOTAL, _QUAD_FLOOR
    if _QUAD is None:
        counts, total = _build_quadgrams()
        _QUAD_TOTAL = total
        _QUAD = {q: math.log(n / total) for q, n in counts.items()}
        # an unseen quadgram is not impossible, just rare
        _QUAD_FLOOR = math.log(0.05 / total)
    return _QUAD


def quadgram_score(text: str) -> float:
    """Mean log-probability per four-letter run. Higher is more English.

    English prose lands near -8.5; a wrong substitution key near -11. That gap
    is far wider than anything the bigram model gives, which is why the
    substitution and Enigma solvers hill-climb on this.
    """
    letters = "".join(c for c in text.upper() if "A" <= c <= "Z")
    n = len(letters)
    if n < 4:
        return -30.0
    table = _quad()
    floor = _QUAD_FLOOR
    total = 0.0
    for i in range(n - 3):
        total += table.get(letters[i:i + 4], floor)
    return total / (n - 3)


_QUAD_INTS = None


def quadgram_table_ints():
    """The same model keyed by a single integer per quadgram.

    The Enigma solver scores a million candidate decryptions; at that volume
    the cost is the dictionary key, so the letters are packed into one int
    (a*17576 + b*676 + c*26 + d) and looked up directly.
    """
    global _QUAD_INTS
    if _QUAD_INTS is None:
        table = _quad()
        packed = {}
        for q, lp in table.items():
            key = ((ord(q[0]) - 65) * 17576 + (ord(q[1]) - 65) * 676
                   + (ord(q[2]) - 65) * 26 + (ord(q[3]) - 65))
            packed[key] = lp
        _QUAD_INTS = packed
    return _QUAD_INTS, _QUAD_FLOOR


def score_ints(values) -> float:
    """Quadgram score for a list of 0-25 letter values."""
    table, floor = quadgram_table_ints()
    n = len(values)
    if n < 4:
        return -30.0
    get = table.get
    total = 0.0
    a, b, c = values[0], values[1], values[2]
    for i in range(3, n):
        d = values[i]
        total += get(a * 17576 + b * 676 + c * 26 + d, floor)
        a, b, c = b, c, d
    return total / (n - 3)


def fitness(text: str) -> float:
    """Quadgram score normalised to roughly 0-1, for mixing with other signals."""
    q = quadgram_score(text)
    return max(0.0, min(1.0, (q + 11.6) / 3.0))
