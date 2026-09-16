"""The Enigma machine, and a solver for it.

The wirings here are the real ones: rotors I-VIII and reflectors B and C as
used by the German army and navy, with the historically correct turnover
notches. Rotors VI, VII and VIII (Kriegsmarine) each have two notches, which
is why they step differently.

How it works, briefly. A key press sends current through the plugboard, then
right-to-left through three (or four) rotors, into the reflector, back
left-to-right through the rotors, and out through the plugboard again. Every
press steps the right-hand rotor first, and the famous double-stepping means
the middle rotor advances both when the right rotor passes its notch and when
the middle rotor is itself sitting on its own notch.

Two properties fall out of the wiring and both matter. Because the reflector
sends the current back through, encryption is its own inverse: the same
settings turn plaintext into ciphertext and back. And because the reflector
never connects a letter to itself, **no letter can ever encrypt to itself** -
the flaw that made cribs work at Bletchley, and the one the solver here uses.
"""
from __future__ import annotations

from .core import ALPHA, Param, Result, ToolError, clamp, tool

CAT = "Classical ciphers"

ROTORS = {
    "I":    ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II":   ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III":  ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    "IV":   ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    "V":    ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
    "VI":   ("JPGVOUMFYQBENHZRDKASXLICTW", "ZM"),
    "VII":  ("NZJHGRCXMYSWBOUFAIVLPEKQDT", "ZM"),
    "VIII": ("FKQHTLXOCBJSPDZRAMEWNIUYGV", "ZM"),
}
REFLECTORS = {
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
    # the thin reflectors, used with the fourth rotor on the naval M4
    "B thin": "ENKQAUYWJICOPBLMDXZVFTHRGS",
    "C thin": "RDOBJNTKVEHMLFCWZAXGYIPSUQ",
}
GREEK = {
    "none": None,
    "Beta": "LEYJVCNIXWPBQMDRTAKZGFUHOS",
    "Gamma": "FSOKANUERHMBTIYCWLQPZXVGJD",
}
ROTOR_NAMES = list(ROTORS)


def _a(c):
    return ord(c) - 65


# --------------------------------------------------------------------------
# A fast integer core, for the solver only
# --------------------------------------------------------------------------
#
# The Machine class below is the readable one and is what the tool uses. The
# solver runs upwards of a million candidate decryptions, so it needs the same
# logic with the strings, attribute lookups and method calls taken out: rotors
# as lists of integers, everything in locals, one flat loop.

_TABLES = {}


def _tables(order):
    key = tuple(order)
    got = _TABLES.get(key)
    if got is None:
        fwd, rev, notch = [], [], []
        for name in order:
            wiring, notches = ROTORS[name]
            f = [ord(c) - 65 for c in wiring]
            b = [0] * 26
            for i, v in enumerate(f):
                b[v] = i
            fwd.append(f)
            rev.append(b)
            notch.append({ord(c) - 65 for c in notches})
        _TABLES[key] = got = (fwd, rev, notch)
    return got


_REFL_INTS = {name: [ord(c) - 65 for c in wiring] for name, wiring in REFLECTORS.items()}


def _fast_run(order, rings, pos, reflector, data, plug=None):
    """Encrypt `data` (list of 0-25) and return the result as a list of ints."""
    (f0, f1, f2), (b0, b1, b2), notch = _tables(order)
    n1, n2 = notch[1], notch[2]
    r0, r1, r2 = rings
    p0, p1, p2 = pos
    refl = _REFL_INTS[reflector]
    out = []
    add = out.append
    for c in data:
        if p1 in n1:                       # double step
            p1 = (p1 + 1) % 26
            p0 = (p0 + 1) % 26
        elif p2 in n2:
            p1 = (p1 + 1) % 26
        p2 = (p2 + 1) % 26
        if plug is not None:
            c = plug[c]
        s = p2 - r2
        c = (f2[(c + s) % 26] - s) % 26
        s = p1 - r1
        c = (f1[(c + s) % 26] - s) % 26
        s = p0 - r0
        c = (f0[(c + s) % 26] - s) % 26
        c = refl[c]
        s = p0 - r0
        c = (b0[(c + s) % 26] - s) % 26
        s = p1 - r1
        c = (b1[(c + s) % 26] - s) % 26
        s = p2 - r2
        c = (b2[(c + s) % 26] - s) % 26
        if plug is not None:
            c = plug[c]
        add(c)
    return out


def _plug_table(pairs):
    table = list(range(26))
    for pair in pairs:
        a, b = ord(pair[0]) - 65, ord(pair[1]) - 65
        table[a], table[b] = b, a
    return table


class Machine:
    """One Enigma, set up and ready to type into."""

    def __init__(self, rotors=("I", "II", "III"), rings=(0, 0, 0), positions=(0, 0, 0),
                 reflector="B", plugboard="", greek=None, greek_ring=0, greek_pos=0):
        if len(rotors) != 3:
            raise ToolError("An Enigma has three rotors (plus an optional fourth on the M4).")
        for r in rotors:
            if r not in ROTORS:
                raise ToolError(f"Unknown rotor {r!r}. Choose from {', '.join(ROTORS)}.")
        if reflector not in REFLECTORS:
            raise ToolError(f"Unknown reflector {reflector!r}.")
        self.names = list(rotors)
        self.wiring = [ROTORS[r][0] for r in rotors]
        self.notches = [ROTORS[r][1] for r in rotors]
        self.rings = [int(x) % 26 for x in rings]
        self.pos = [int(x) % 26 for x in positions]
        self.reflector = REFLECTORS[reflector]
        self.greek = GREEK.get(greek) if isinstance(greek, str) else greek
        self.greek_ring = int(greek_ring) % 26
        self.greek_pos = int(greek_pos) % 26
        self.plug = self._plugboard(plugboard)

    @staticmethod
    def _plugboard(spec):
        table = {c: c for c in ALPHA}
        if not spec:
            return table
        pairs = spec.upper().replace(",", " ").replace("-", " ").split()
        used = set()
        for pair in pairs:
            letters = [c for c in pair if c in ALPHA]
            if len(letters) != 2:
                raise ToolError(f"Plugboard pair {pair!r} should be two letters, such as AB.")
            a, b = letters
            if a in used or b in used:
                raise ToolError(f"{a} or {b} is plugged more than once.")
            used.update((a, b))
            table[a], table[b] = b, a
        if len(pairs) > 13:
            raise ToolError("There are only thirteen cables.")
        return table

    def _step(self):
        """Advance the rotors, including the double-step of the middle one."""
        right_at_notch = ALPHA[self.pos[2]] in self.notches[2]
        middle_at_notch = ALPHA[self.pos[1]] in self.notches[1]
        if middle_at_notch:                      # the double step
            self.pos[1] = (self.pos[1] + 1) % 26
            self.pos[0] = (self.pos[0] + 1) % 26
        elif right_at_notch:
            self.pos[1] = (self.pos[1] + 1) % 26
        self.pos[2] = (self.pos[2] + 1) % 26

    def _through(self, i, c, reverse=False):
        shift = self.pos[i] - self.rings[i]
        idx = (_a(c) + shift) % 26
        if reverse:
            out = self.wiring[i].index(ALPHA[idx])
        else:
            out = _a(self.wiring[i][idx])
        return ALPHA[(out - shift) % 26]

    def _through_greek(self, c, reverse=False):
        if not self.greek:
            return c
        shift = self.greek_pos - self.greek_ring
        idx = (_a(c) + shift) % 26
        if reverse:
            out = self.greek.index(ALPHA[idx])
        else:
            out = _a(self.greek[idx])
        return ALPHA[(out - shift) % 26]

    def press(self, c):
        self._step()
        c = self.plug[c]
        for i in (2, 1, 0):
            c = self._through(i, c)
        c = self._through_greek(c)
        c = self.reflector[_a(c)]
        c = self._through_greek(c, reverse=True)
        for i in (0, 1, 2):
            c = self._through(i, c, reverse=True)
        return self.plug[c]

    def run(self, text):
        out = []
        for ch in text.upper():
            if ch in ALPHA:
                out.append(self.press(ch))
        return "".join(out)


def _settings(rotor1, rotor2, rotor3, rings, positions, reflector, plugboard,
              greek, greek_ring, greek_pos):
    def triple(value, label):
        body = str(value or "").upper().replace(",", " ").split()
        if len(body) == 1 and len(body[0]) == 3 and body[0].isalpha():
            body = list(body[0])
        if len(body) != 3:
            raise ToolError(f"{label} needs three values - either letters like 'AAA' "
                            "or numbers like '1 1 1'.")
        out = []
        for item in body:
            if item.isdigit():
                out.append((int(item) - 1) % 26)
            elif len(item) == 1 and item in ALPHA:
                out.append(_a(item))
            else:
                raise ToolError(f"{label}: {item!r} is not a letter or a number 1-26.")
        return out
    return Machine(rotors=(rotor1, rotor2, rotor3),
                   rings=triple(rings, "Ring settings"),
                   positions=triple(positions, "Start positions"),
                   reflector=reflector, plugboard=plugboard,
                   greek=(None if greek == "none" else greek),
                   greek_ring=(_a(str(greek_ring).upper()[0]) if str(greek_ring)[:1].isalpha()
                               else int(greek_ring or 1) - 1),
                   greek_pos=(_a(str(greek_pos).upper()[0]) if str(greek_pos)[:1].isalpha()
                              else int(greek_pos or 1) - 1))


def _enigma(text, rotor1="I", rotor2="II", rotor3="III", rings="AAA", positions="AAA",
            reflector="B", plugboard="", greek="none", greek_ring="A", greek_pos="A",
            groups=5):
    machine = _settings(rotor1, rotor2, rotor3, rings, positions, reflector,
                        plugboard, greek, greek_ring, greek_pos)
    out = machine.run(text)
    groups = clamp(groups, 0, 20, 5)
    shown = (" ".join(out[i:i + groups] for i in range(0, len(out), groups))
             if groups else out)
    final = "".join(ALPHA[p] for p in machine.pos)
    return Result(text=shown,
                  note=(f"Rotors {rotor1}-{rotor2}-{rotor3}, reflector {reflector}"
                        + (f", {greek} fourth rotor" if greek != "none" else "")
                        + f". Rotors finished at {final}. "
                          "Enigma is its own inverse - the same settings undo it."))


tool(id="enigma", name="Enigma machine", category=CAT,
     summary="The real rotor wirings, notches, plugboard and double-stepping",
     explain=(
         "A faithful Enigma. Rotors I to VIII with their historical wirings and turnover "
         "notches, reflectors B and C, the Beta and Gamma fourth rotors and thin reflectors "
         "of the naval M4, a thirteen-cable plugboard, and the double-stepping quirk of the "
         "middle rotor.\n\n"
         "Current goes from the key through the plugboard, right to left through the rotors, "
         "into the reflector, back left to right, and out through the plugboard again. Two "
         "things follow from that. Encryption is its own inverse, so the same settings that "
         "scramble a message unscramble it - there is no separate decode button because there "
         "does not need to be. And because the reflector never wires a letter to itself, no "
         "letter can ever come out as itself. That single flaw is what made guessed cribs "
         "work at Bletchley, and it is what the Enigma solver here uses.\n\n"
         "Settings take either letters (AAA) or numbers (1 1 1), as the original key sheets "
         "did. Ring settings move the wiring relative to the letter ring; start positions are "
         "what you see in the windows."),
     example="Rotors I-II-III, rings AAA, start AAA: HELLOWORLD -> ILBDAAMTAZ",
     security="Broken in the 1940s and comprehensively broken now. History, not security.",
     tags=["enigma", "rotor", "wehrmacht", "bletchley", "turing", "m4", "kriegsmarine",
           "plugboard", "wwii", "machine"],
     params=[Param("rotor1", "Left rotor", "choice", "I", choices=ROTOR_NAMES),
             Param("rotor2", "Middle rotor", "choice", "II", choices=ROTOR_NAMES),
             Param("rotor3", "Right rotor", "choice", "III", choices=ROTOR_NAMES),
             Param("positions", "Start positions", "text", "AAA", width=8,
                   help="What shows in the windows, e.g. AAA or 1 1 1."),
             Param("rings", "Ring settings", "text", "AAA", width=8,
                   help="Ringstellung - the wiring offset inside each rotor."),
             Param("reflector", "Reflector", "choice", "B", choices=list(REFLECTORS)),
             Param("plugboard", "Plugboard", "text", "", width=26,
                   help="Pairs, e.g. 'AB CD EF'. Up to thirteen cables."),
             Param("greek", "Fourth rotor (M4)", "choice", "none", choices=list(GREEK),
                   help="Naval M4 only, and it needs a thin reflector."),
             Param("greek_pos", "Fourth rotor position", "text", "A", width=6,
                   visible_when=lambda v: v.get("greek", "none") != "none"),
             Param("greek_ring", "Fourth ring setting", "text", "A", width=6,
                   visible_when=lambda v: v.get("greek", "none") != "none"),
             Param("groups", "Group output in", "int", 5, minimum=0, maximum=20,
                   help="Letters per group, as signals were sent. 0 for none.")],
     encode=_enigma, decode=_enigma,
     encode_label="Run through", decode_label="Run through (same thing)")


# --------------------------------------------------------------------------
# Breaking it
# --------------------------------------------------------------------------

MAX_CRACK_LETTERS = 400
PREFIX_LETTERS = 48
MID_LETTERS = 160
KEEP_PER_ORDER = 12      # candidates carried out of each rotor order
KEEP_MID = 80            # survivors of the medium-length re-score
KEEP_FULL = 8            # settings taken as far as the ring sweep
KEEP_PLUG = 4            # settings given their own plugboard hill-climb


def _narrow(pool, text, reflector, keep, score_ints, base=(0, 0, 0)):
    """Re-score a pool of candidate settings on more text and keep the best."""
    out = [(score_ints(_fast_run(order, base, pos, reflector, text)), order, pos)
           for _s, order, pos in pool]
    out.sort(reverse=True, key=lambda t: t[0])
    return out[:keep]


def _plug_climb(order, rings, positions, reflector, data, limit, score,
                score_ints, should_stop=None, plugs=None):
    """Add plugboard cables greedily, then try swapping each one for a better.

    Every added cable that is right lifts the score sharply, so greed works;
    but an early wrong guess can block a right one, which is what the second
    pass undoes.
    """
    plugs = list(plugs or [])
    used = set("".join(plugs))
    while len(plugs) < limit:
        if should_stop and should_stop():
            break
        candidate = None
        for i, a in enumerate(ALPHA):
            if a in used:
                continue
            for b in ALPHA[i + 1:]:
                if b in used:
                    continue
                table = _plug_table(plugs + [a + b])
                s = score_ints(_fast_run(order, rings, positions, reflector, data, table))
                if candidate is None or s > candidate[0]:
                    candidate = (s, a + b)
        if candidate is None or candidate[0] <= score + 0.005:
            break
        score, pair = candidate
        plugs.append(pair)
        used.update(pair)

    for _pass in range(2):
        improved = False
        for idx in range(len(plugs)):
            if should_stop and should_stop():
                return score, plugs
            rest = plugs[:idx] + plugs[idx + 1:]
            free = [c for c in ALPHA if c not in set("".join(rest))]
            best = (score, plugs[idx])
            for i, a in enumerate(free):
                for b in free[i + 1:]:
                    table = _plug_table(rest + [a + b])
                    s = score_ints(_fast_run(order, rings, positions, reflector,
                                             data, table))
                    if s > best[0] + 1e-9:
                        best = (s, a + b)
            if best[1] != plugs[idx]:
                score, plugs[idx] = best[0], best[1]
                improved = True
        if not improved:
            break
    return score, plugs



# --- the crib attack ------------------------------------------------------
#
# No letter can ever stand for itself, so a guessed word can only sit where it
# disagrees with the ciphertext everywhere - which throws out over half the
# places it might go before any rotors are turned. At the rest, the rotors are
# swept and the guess is scored by how many of its letters come out right with
# no plugboard at all. Cables spoil some of them, but a letter is untouched
# unless one of its cables happens to catch it, so the right setting still
# shows a run of hits where a wrong one shows almost none.

CRIB_KEEP = 700          # settings carried out of the crib sweep
CRIB_PLUG_KEEP = 140     # settings given a plugboard climb against the crib


def _crib_offsets(letters, crib, window):
    """Every place the crib could sit, by the no-self-encryption rule."""
    out = []
    for off in range(0, window + 1):
        if off + len(crib) > len(letters):
            break
        if all(letters[off + i] != crib[i] for i in range(len(crib))):
            out.append(off)
    return out


def _crib_hits(dec_bytes, offsets, crib_int, n):
    """Best crib match over the allowed offsets, counted at C speed."""
    best, best_off = -1, 0
    for off in offsets:
        x = int.from_bytes(dec_bytes[off:off + n], "big") ^ crib_int
        m = x.to_bytes(n, "big").count(0)
        if m > best:
            best, best_off = m, off
    return best, best_off


def _crib_plug_climb(order, rings, pos, reflector, window, off, crib_ints, limit,
                     should_stop=None):
    """Add cables to make as much of the crib come out right as possible."""
    n = len(crib_ints)
    end = off + n

    def hits(table):
        dec = _fast_run(order, rings, pos, reflector, window[:end], table)
        return sum(1 for i in range(n) if dec[off + i] == crib_ints[i])

    plugs, used, score = [], set(), hits(None)
    while len(plugs) < limit and score < n:
        if should_stop and should_stop():
            break
        cand = None
        for i, a in enumerate(ALPHA):
            if a in used:
                continue
            for b in ALPHA[i + 1:]:
                if b in used:
                    continue
                s = hits(_plug_table(plugs + [a + b]))
                if cand is None or s > cand[0]:
                    cand = (s, a + b)
        if cand is None or cand[0] <= score:
            break
        score, pair = cand
        plugs.append(pair)
        used.update(pair)
    return score, plugs


def _crack_with_crib(letters, data, orders, reflector, crib, window, limit,
                     score_ints, known_rings=None, on_progress=None, should_stop=None):
    crib_ints = [ord(c) - 65 for c in crib]
    n = len(crib_ints)
    offsets = _crib_offsets(letters, crib, window)
    if not offsets:
        raise ToolError(
            "That crib cannot sit anywhere in the first "
            f"{window + n} letters - at every place, one of its letters lines up "
            "with the same letter in the ciphertext, which Enigma can never do. "
            "Either the crib is wrong or it appears later in the message.")
    span = max(offsets) + n
    win = data[:span]
    crib_int = int.from_bytes(bytes(crib_ints), "big")
    base = known_rings or (0, 0, 0)

    keep, cut, tried = [], max(2, n // 5), 0
    for k, order in enumerate(orders):
        if should_stop and should_stop():
            break
        for p0 in range(26):
            for p1 in range(26):
                for p2 in range(26):
                    dec = bytes(_fast_run(order, base, (p0, p1, p2), reflector, win))
                    m, off = _crib_hits(dec, offsets, crib_int, n)
                    if m > cut:
                        keep.append((m, order, (p0, p1, p2), off))
                        if len(keep) > CRIB_KEEP * 20:
                            keep.sort(reverse=True, key=lambda t: t[0])
                            del keep[CRIB_KEEP:]
                            cut = max(cut, keep[-1][0] - 1)
        tried += 17576
        if on_progress:
            on_progress(k + 1, len(orders), float(cut), order)
    if not keep:
        raise ToolError("Nothing matched the crib. Try a different guess, or a "
                        "wider search window if the word appears further in.")
    keep.sort(reverse=True, key=lambda t: t[0])
    del keep[CRIB_KEEP:]

    # cables, chosen to make the crib come out right
    plugged = []
    for m, order, pos, off in keep[:CRIB_PLUG_KEEP]:
        if should_stop and should_stop():
            break
        hit, plugs = _crib_plug_climb(order, base, pos, reflector, win, off,
                                      crib_ints, limit, should_stop)
        table = _plug_table(plugs) if plugs else None
        q = score_ints(_fast_run(order, base, pos, reflector, data, table))
        plugged.append((hit / n + q / 40.0, q, order, pos, plugs))
    plugged.sort(reverse=True, key=lambda t: t[0])

    # rings and a final polish on the whole message, best few only
    best = None
    for _r, q, order, pos, plugs in plugged[:4]:
        if should_stop and should_stop():
            break
        table = _plug_table(plugs) if plugs else None
        cur = (q, base, pos)
        if known_rings is None:
            for ring1 in range(26):
                for ring2 in range(26):
                    p = (pos[0], (pos[1] + ring1) % 26, (pos[2] + ring2) % 26)
                    s = score_ints(_fast_run(order, (0, ring1, ring2), p, reflector,
                                             data, table))
                    if s > cur[0]:
                        cur = (s, (0, ring1, ring2), p)
        q2, rings, p = cur
        q2, plugs = _plug_climb(order, rings, p, reflector, data, limit, q2,
                                score_ints, should_stop, plugs)
        if best is None or q2 > best[0]:
            best = (q2, order, rings, p, plugs)
    return best[0], best[1], best[2], best[3], best[4], tried


def crack(ciphertext, rotor_choice=None, reflector="B", max_plugs=8,
          crib="", crib_window=16, known_rings=None,
          on_progress=None, should_stop=None):
    """Recover Enigma settings from ciphertext alone.

    The same three-stage attack the codebreakers used, in the order they used
    it, because the full key space is far too large to sweep:

    1. **Rotor order and window positions.** Every ordering of the rotors you
       allow against all 17,576 positions, each decryption scored on
       four-letter English statistics. The plugboard is left out: it makes
       every score worse, but not so much that the right rotor order stops
       standing out. A short prefix is used for the sweep and the best
       candidates are then re-scored on the whole message.
    2. **Ring settings.** With the order fixed, walk the middle and right
       rings, moving each rotor's position with its ring since the two shift
       together.
    3. **Plugboard.** Add cables one at a time, always the pair that improves
       the score most, stopping when none does. Turing's own hill-climb.
    """
    import itertools
    from .language import score_ints
    letters = "".join(c for c in ciphertext.upper() if c in ALPHA)
    if len(letters) < 40:
        raise ToolError("Enigma needs a reasonable amount of ciphertext - at least 40 "
                        "letters, and a couple of hundred is far better.")
    names = [r.strip().upper() for r in (rotor_choice or ["I", "II", "III", "IV", "V"])]
    for r in names:
        if r not in ROTORS:
            raise ToolError(f"Unknown rotor {r!r}. Choose from {', '.join(ROTORS)}.")
    if len(names) < 3:
        raise ToolError("Give at least three rotors to choose between.")

    data = [ord(c) - 65 for c in letters[:MAX_CRACK_LETTERS]]
    prefix = data[:PREFIX_LETTERS]
    orders = list(itertools.permutations(names, 3))
    limit = clamp(max_plugs, 0, 13, 8)

    crib = "".join(c for c in (crib or "").upper() if c in ALPHA)
    if crib:
        if len(crib) < 6:
            raise ToolError("A crib needs at least six letters to be worth anything; "
                            "a dozen or more is much better.")
        if len(crib) > len(letters):
            raise ToolError("The crib is longer than the message.")
        score, order, rings, positions, plugs, tried = _crack_with_crib(
            letters, data, orders, reflector, crib,
            clamp(crib_window, 0, 200, 16), limit, score_ints, known_rings,
            on_progress, should_stop)
        machine = Machine(order, rings, positions, reflector, " ".join(plugs))
        return {"rotors": order, "rings": rings, "positions": positions,
                "reflector": reflector, "plugs": plugs, "score": score,
                "plaintext": machine.run(letters), "tried": tried, "crib": crib}

    # --- 1: rotor order and window positions
    #
    # A sweep of every order against all 17,576 positions, scored on a short
    # prefix. The right setting does beat the rest even with cables in, but
    # often only narrowly, so a wide shortlist is kept and then narrowed on
    # progressively more text rather than one winner being picked per order.
    base = known_rings or (0, 0, 0)
    pool = []
    tried = 0
    for n, order in enumerate(orders):
        if should_stop and should_stop():
            break
        local = []
        for p0 in range(26):
            for p1 in range(26):
                for p2 in range(26):
                    s = score_ints(_fast_run(order, base, (p0, p1, p2),
                                              reflector, prefix))
                    local.append((s, (p0, p1, p2)))
        local.sort(reverse=True, key=lambda t: t[0])
        for s, pos in local[:KEEP_PER_ORDER]:
            pool.append((s, order, pos))
        tried += 17576
        if on_progress:
            on_progress(n + 1, len(orders), local[0][0], order)
    if not pool:
        raise ToolError("Stopped before anything was found.")

    # narrow on more text, in two steps - a short prefix flatters the wrong
    # settings, and re-scoring everything on the whole message is wasteful
    mid = data[:MID_LETTERS]
    pool = _narrow(pool, mid, reflector, KEEP_MID, score_ints, base)
    pool = _narrow(pool, data, reflector, KEEP_FULL, score_ints, base)

    # --- 2: ring settings, for each surviving candidate
    ringed = []
    for s0, order, pos0 in pool:
        if should_stop and should_stop():
            break
        if known_rings is not None:
            ringed.append((s0, order, base, pos0))
            continue
        best = (-1e9, None, None)
        for ring1 in range(26):
            for ring2 in range(26):
                pos = (pos0[0], (pos0[1] + ring1) % 26, (pos0[2] + ring2) % 26)
                s = score_ints(_fast_run(order, (0, ring1, ring2), pos, reflector, data))
                if s > best[0]:
                    best = (s, (0, ring1, ring2), pos)
        ringed.append((best[0], order, best[1], best[2]))
    if not ringed:
        raise ToolError("Stopped before anything was found.")
    ringed.sort(reverse=True, key=lambda t: t[0])

    # --- 3: plugboard, on each of the best few
    #
    # Cables are added one at a time, always the pair that improves the score
    # most - Turing's own hill-climb. Which candidate is really right often
    # only becomes clear once its cables are in, so several are taken this far
    # and compared afterwards.
    results = []
    for score, order, rings, positions in ringed[:KEEP_PLUG]:
        if should_stop and should_stop():
            break
        score, plugs = _plug_climb(order, rings, positions, reflector, data,
                                   limit, score, score_ints, should_stop)
        # with the cables in, the ring settings are worth another look, and
        # then the cables again - the two inform each other
        if plugs and known_rings is None:
            table = _plug_table(plugs)
            best = (score, rings, positions)
            for ring1 in range(26):
                for ring2 in range(26):
                    pos = (positions[0],
                           (positions[1] - rings[1] + ring1) % 26,
                           (positions[2] - rings[2] + ring2) % 26)
                    s = score_ints(_fast_run(order, (0, ring1, ring2), pos,
                                             reflector, data, table))
                    if s > best[0]:
                        best = (s, (0, ring1, ring2), pos)
            score, rings, positions = best
            score, plugs = _plug_climb(order, rings, positions, reflector, data,
                                       limit, score, score_ints, should_stop, plugs)
        results.append((score, order, rings, positions, plugs))
    if not results:
        raise ToolError("Stopped before anything was found.")
    results.sort(reverse=True, key=lambda t: t[0])
    score, order, rings, positions, plugs = results[0]

    machine = Machine(order, rings, positions, reflector, " ".join(plugs))
    return {
        "rotors": order, "rings": rings, "positions": positions,
        "reflector": reflector, "plugs": plugs, "score": score,
        "plaintext": machine.run(letters), "tried": tried, "crib": "",
    }


def _enigma_crack(text, rotors="I II III IV V", reflector="B", max_plugs=8,
                  crib="", rings="unknown", crib_window=12):
    from .language import fitness
    chosen = [r.strip().upper() for r in rotors.replace(",", " ").split() if r.strip()]
    if len(chosen) < 3:
        raise ToolError("Give at least three rotors to choose between, e.g. 'I II III IV V'.")
    if len(chosen) > 6:
        raise ToolError("More than six rotors to permute would take a very long time. "
                        "Narrow it down if you can.")
    known = None
    ring_text = (rings or "").strip().upper()
    if ring_text and ring_text not in ("UNKNOWN", "?"):
        letters = "".join(c for c in ring_text if c in ALPHA)
        if len(letters) != 3:
            raise ToolError("Ring settings must be three letters, e.g. 'AAA', or "
                            "'unknown' to search for them.")
        known = tuple(ord(c) - 65 for c in letters)
    got = crack(text, chosen, reflector, int(max_plugs), crib=crib,
                crib_window=int(crib_window), known_rings=known)
    ring_out = "".join(ALPHA[r] for r in got["rings"])
    positions = "".join(ALPHA[p] for p in got["positions"])
    conf = fitness(got["plaintext"])
    rows = [("Rotors", " - ".join(got["rotors"])),
            ("Reflector", got["reflector"]),
            ("Ring settings", ring_out + ("" if known else "  (searched)")),
            ("Start positions", positions),
            ("Plugboard", " ".join(got["plugs"]) or "(none found)"),
            ("Looks like English", f"{conf:.0%}"),
            ("Settings tried", f"{got['tried']:,}")]
    if conf >= 0.55:
        note = (f"Rotors {' - '.join(got['rotors'])}, rings {ring_out}, start {positions}"
                + (f", plugboard {' '.join(got['plugs'])}" if got["plugs"] else "")
                + ". Put these into the Enigma tool to check.")
        warn = ""
    else:
        note = ("This is the best setting found, but the result does not read as English, "
                "so it is probably not the right one.")
        warn = ("Nothing readable came out. Enigma with a full plugboard cannot be "
                   "broken from ciphertext alone at this length - that is what the bombes "
                "were for. Two things move the odds a great deal: a crib (a word or "
                "phrase you expect to appear, ideally at the opening), and the ring "
                "settings if you know them. With both, it recovers everything exactly "
                "through five or six cables.")
    return Result(text=got["plaintext"], rows=rows, headers=["Setting", "Value"],
                  prefer="text", note=note, warn=warn)


tool(id="enigma-crack", name="Enigma solver", category=CAT,
     summary="Recovers rotor order, positions, rings and plugboard from ciphertext",
     explain=(
         "Works out Enigma settings from the ciphertext, in stages, because the full key "
         "space is far too large to sweep.\n\n"
         "With no crib: every ordering of the rotors you allow is tried against all 17,576 "
         "window positions, each decryption scored on four-letter English statistics, with "
         "the plugboard left out. The survivors get a ring sweep, and then cables are added "
         "one at a time - always the cable that improves the score most, until none does, "
         "which is Turing's own hill-climb.\n\n"
         "With a crib it is much stronger, and much closer to how it was really done. No "
         "letter can ever stand for itself, so a guessed word can only sit where it "
         "disagrees with the ciphertext at every position - that alone throws out more than "
         "half the places it could go. The rest are swept, and a setting is judged by how "
         "many of the crib's letters come out right with no plugboard at all. Cables spoil "
         "some of them, but a letter is left alone unless a cable happens to catch it, so "
         "the true setting still shows a run of hits where a wrong one shows almost none. "
         "The cables are then chosen to make the rest of the crib come out right.\n\n"
         "What to expect. No plugboard: it will find the settings from a couple of hundred "
         "letters on its own. A few cables: give it a crib. A crib and the ring settings "
         "together: exact recovery through five or six cables in well under a minute. A "
         "full ten-cable plugboard with unknown rings and no crib is beyond it, and beyond "
         "anything that is not a bombe - say so rather than trusting the output.\n\n"
         "Five rotors to choose between means sixty orderings; a sixth makes it a hundred "
         "and twenty and takes twice as long."),
     tags=["enigma", "crack", "solve", "bletchley", "turing", "bombe", "rotor", "crib"],
     params=[Param("rotors", "Rotors it may have used", "text", "I II III IV V", width=22,
                   help="Three to six of I-VIII. More is slower - sixty orderings for five."),
             Param("reflector", "Reflector", "choice", "B", choices=["B", "C"]),
             Param("crib", "Crib (a word you expect)", "text", "", width=26,
                   help="A word or phrase you think is in the message, ideally at the "
                        "start. Sixteen letters or more is what makes it work; a short crib "
                        "is drowned out by chance matches."),
             Param("crib_window", "Search the first", "int", 8, minimum=0, maximum=60,
                   help="How many letters in to look for the crib. Wider is slower.",
                   visible_when=lambda v: bool((v.get("crib") or "").strip())),
             Param("rings", "Ring settings, if known", "text", "unknown", width=12,
                   help="Three letters, e.g. 'AAA'. Knowing them makes the search far "
                        "more reliable. Leave as 'unknown' to search for them."),
             Param("max_plugs", "Most cables to look for", "int", 8, minimum=0, maximum=13)],
     action=_enigma_crack, action_label="Break it")
