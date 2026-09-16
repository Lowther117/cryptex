"""Digital modes off the air: RTTY, PSK31 and AX.25 packet.

Three modes that between them cover most of what you will hear in the noisy
part of an amateur band, and all three work the same way at heart: a carrier
is moved - in frequency, or in phase - and the receiver watches it move.

* **RTTY** shifts between two tones, a mark and a space, 170 Hz apart at
  45.45 baud. Underneath it is Baudot, the same five-bit teleprinter code
  from 1901, which is why it cannot send lower case.
* **PSK31** flips the *phase* of a single steady tone instead, at 31.25 baud,
  which fits a conversation into the width of a whisper - about 60 Hz. The
  character set is varicode, where the commonest letters get the shortest
  codes, and a run of two zeros marks the gap between characters.
* **AX.25 packet** is what carries APRS position beacons. 1200 baud, Bell 202
  tones of 1200 and 2200 Hz, HDLC framing with a CRC. Every packet is
  addressed, checksummed and routed, which makes it the only one of the three
  you can actually trust the contents of.

Everything here reads any audio or video file, and writes plain WAV.
"""
from __future__ import annotations

import os
import wave

from .core import Param, Result, ToolError, clamp, default_save_dir, need, to_text, tool
from .signals import MEDIA_TYPES, _np, load_audio

CAT = "Signals"


def _write_wav(path, samples, rate):
    np = _np()
    data = np.clip(np.asarray(samples), -1.0, 1.0)
    pcm = (data * 32000.0).astype("<i2")
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm.tobytes())
    return len(data) / rate


def _stretch(values, rate, baud):
    """One value per symbol -> one value per sample, at the exact symbol rate.

    Repeating each symbol a whole number of samples looks harmless and is not:
    at 11025 Hz a PSK31 symbol is 352.8 samples, and rounding to 353 puts the
    transmission 0.06% slow, which is enough to slip a whole bit inside a long
    message. Indexing by time instead keeps it exact.
    """
    np = _np()
    arr = np.asarray(values, dtype=np.float64)
    total = int(len(arr) * rate / baud)
    idx = np.minimum((np.arange(total) * baud / rate).astype(np.int64), len(arr) - 1)
    return arr[idx]


def _tone_track(samples, rate, f1, f2, baud, bandwidth=None):
    """How much more of tone f1 than f2 is present, sample by sample.

    Two matched filters, one per tone, each a complex mix down to DC followed
    by a moving average one symbol long. The difference in magnitude is
    positive for one tone and negative for the other, which is the bit.
    """
    np = _np()
    x = samples.astype(np.float64)
    n = x.size
    t = np.arange(n) / rate
    win = max(4, int(rate / baud * (bandwidth or 1.0)))
    kernel = np.ones(win) / win

    def power(freq):
        mixed = x * np.exp(-2j * np.pi * freq * t)
        smooth = np.convolve(mixed, kernel, mode="same")
        return np.abs(smooth)

    return power(f1) - power(f2), win


def _clock(track, rate, baud, invert=False):
    """Slice a soft bit track at symbol centres, recovering the clock from the
    signal's own transitions rather than assuming it starts on one."""
    np = _np()
    sign = -1.0 if invert else 1.0
    bits = (sign * track) > 0
    spb = rate / baud
    # where the bit stream changes is where the transmitter's clock ticked;
    # the average distance of those edges from a whole symbol is the offset
    edges = np.flatnonzero(np.diff(bits.astype(np.int8)) != 0)
    if edges.size < 4:
        phase = spb / 2.0
    else:
        ang = np.angle(np.mean(np.exp(2j * np.pi * edges / spb)))
        phase = (ang / (2 * np.pi)) * spb % spb + spb / 2.0
    idx = np.arange(phase, len(bits) - 1, spb).astype(np.int64)
    idx = idx[(idx >= 0) & (idx < len(bits))]
    return bits[idx], idx


# --------------------------------------------------------------------------
# RTTY
# --------------------------------------------------------------------------

def _rtty_decode(path, baud=45.45, shift=170.0, centre=0.0, reverse=False,
                 stop_bits=1.5, unshift_on_space=True):
    np = _np()
    from .encodings import BAUDOT_F, BAUDOT_L
    samples, rate = load_audio(path)
    baud = float(clamp(baud, 10.0, 1200.0, 45.45))
    shift = float(clamp(shift, 20.0, 2000.0, 170.0))
    if centre <= 0:
        centre = _find_centre(samples, rate, shift)
    mark, space = centre + shift / 2.0, centre - shift / 2.0
    track, _win = _tone_track(samples, rate, mark, space, baud)

    best = None
    for inv in ((False, True) if not reverse else (True, False)):
        bits, _idx = _clock(track, rate, baud, invert=inv)
        text, chars = _baudot_stream(bits, BAUDOT_L, BAUDOT_F, stop_bits,
                                     unshift_on_space)
        score = _printable(text)
        if best is None or score > best[0]:
            best = (score, text, chars, inv)
    score, text, chars, inv = best
    if not text.strip():
        return Result(warn="Nothing decoded. Check the baud rate and shift, and that the "
                           "recording really is RTTY - the spectrogram tool will show you "
                           "two tones side by side if it is.")
    return Result(text=text,
                  rows=[("Characters", chars), ("Baud", f"{baud:g}"),
                        ("Shift", f"{shift:g} Hz"),
                        ("Mark / space", f"{mark:.0f} / {space:.0f} Hz"),
                        ("Polarity", "reversed" if inv else "normal"),
                        ("Looks like text", f"{score:.0%}")],
                  headers=["", ""], prefer="text",
                  note=f"{chars} character(s) at {baud:g} baud, {shift:g} Hz shift"
                       + (", polarity reversed." if inv else "."),
                  warn=None if score > 0.6 else
                       "The result does not read cleanly. Try swapping the polarity by "
                       "hand, or a different shift - 170 Hz is amateur, 425 and 850 Hz "
                       "turn up on commercial and weather circuits.")


def _find_centre(samples, rate, shift):
    """Find the pair of tones by looking for the two strongest peaks the right
    distance apart in the spectrum."""
    np = _np()
    n = min(len(samples), 1 << 18)
    seg = samples[:n] * np.hanning(n)
    mag = np.abs(np.fft.rfft(seg))
    freqs = np.fft.rfftfreq(n, 1.0 / rate)
    band = (freqs > 200) & (freqs < 3500)
    mag, freqs = mag[band], freqs[band]
    if mag.size < 8:
        return 2210.0
    top = int(np.argmax(mag))
    gap = int(round(shift / (freqs[1] - freqs[0])))
    lo, hi = max(0, top - gap - 3), min(mag.size, top - gap + 4)
    up_lo, up_hi = max(0, top + gap - 3), min(mag.size, top + gap + 4)
    below = mag[lo:hi].max() if hi > lo else 0.0
    above = mag[up_lo:up_hi].max() if up_hi > up_lo else 0.0
    other = freqs[lo:hi][int(np.argmax(mag[lo:hi]))] if below >= above and hi > lo else \
        (freqs[up_lo:up_hi][int(np.argmax(mag[up_lo:up_hi]))] if up_hi > up_lo else freqs[top])
    return float((freqs[top] + other) / 2.0)


def _baudot_stream(bits, letters, figures, stop_bits, unshift_on_space):
    """Pick characters out of a raw bit stream: hunt for a start bit, take the
    next five, check the stop bit is there, repeat."""
    out, figs, i, chars = [], False, 0, 0
    n = len(bits)
    stop = max(1, int(round(stop_bits)))
    while i < n - 7:
        if bits[i]:                 # mark - the idle state, not a start bit
            i += 1
            continue
        value = 0
        for b in range(5):
            value |= int(bool(bits[i + 1 + b])) << b
        if not bits[min(n - 1, i + 6)]:
            i += 1                  # stop bit missing: this was not a character
            continue
        c = (figures if figs else letters)[value]
        if c == "\x0e":
            figs = True          # FIGS
        elif c == "\x0f":
            figs = False         # LTRS
        else:
            if c == " " and unshift_on_space:
                figs = False
            if c not in ("\x00",):
                out.append(c)
                chars += 1
        i += 6 + stop
    return "".join(out), chars


def _printable(text):
    if not text:
        return 0.0
    good = sum(1 for c in text if c.isalnum() or c in " .,:;!?'-/()\r\n")
    return good / len(text)


def _rtty_encode(data, baud=45.45, shift=170.0, centre=2210.0, rate=11025,
                 lead_in=1.0, outdir=""):
    np = _np()
    from .encodings import BAUDOT_F, BAUDOT_L
    text = to_text(data)
    if not text.strip():
        raise ToolError("Type something to send.")
    # Baudot with "unshift on space": after a space, send FIGS again before the
    # next digit, so a receiver that resets on space stays with us.
    figs_code, ltrs_code = BAUDOT_L.index("\x0e"), BAUDOT_L.index("\x0f")
    codes, figs = [], False
    for c in text.upper():
        if c in BAUDOT_L and not (figs and c in BAUDOT_F and c != " "):
            if figs:
                codes.append(ltrs_code)
                figs = False
            codes.append(BAUDOT_L.index(c))
        elif c in BAUDOT_F:
            if not figs:
                codes.append(figs_code)
                figs = True
            codes.append(BAUDOT_F.index(c))
        if c == " ":
            figs = False
    baud = float(clamp(baud, 10.0, 1200.0, 45.45))
    shift = float(clamp(shift, 20.0, 2000.0, 170.0))
    rate = int(clamp(rate, 8000, 48000, 11025))
    mark, space = centre + shift / 2.0, centre - shift / 2.0

    symbols = [mark] * int(baud * float(clamp(lead_in, 0.0, 10.0, 1.0)))
    for code in codes:
        symbols.append(space)                       # start
        for b in range(5):
            symbols.append(mark if (code >> b) & 1 else space)
        symbols += [mark, mark]                     # 1.5 stop bits, rounded up
    symbols += [mark] * int(baud * 0.5)

    freq = _stretch(symbols, rate, baud)
    phase = np.cumsum(2 * np.pi * freq / rate)
    audio = 0.7 * np.sin(phase)

    dest = os.path.join(outdir or default_save_dir(), "rtty.wav")
    secs = _write_wav(dest, audio, rate)
    return Result(file_path=dest,
                  rows=[("Characters", len(codes)), ("Baud", f"{baud:g}"),
                        ("Shift", f"{shift:g} Hz"),
                        ("Mark / space", f"{mark:.0f} / {space:.0f} Hz"),
                        ("Length", f"{secs:.1f} s"), ("Saved to", dest)],
                  headers=["", ""],
                  note=f"{secs:.1f} seconds written to {dest}.")


tool(id="rtty", name="RTTY (radioteletype)", category=CAT,
     summary="Decode or generate 45.45 baud Baudot teleprinter signals",
     explain=(
         "RTTY is the oldest digital mode still in daily use and it sounds like a "
         "warbling two-note chirp. The transmitter has two frequencies, a mark and a "
         "space, and it hops between them; amateurs use 170 Hz apart at 45.45 baud, "
         "which is 60 words a minute, the speed of a mechanical teleprinter in 1930.\n\n"
         "Underneath it is Baudot - five bits per character, with shift codes to swap "
         "between letters and figures. Five bits is only thirty-two possibilities, which "
         "is why RTTY has no lower case and why a missed shift code turns the rest of a "
         "line into numbers.\n\n"
         "This finds the two tones for you, recovers the timing from the signal itself, "
         "and tries both polarities - getting mark and space the wrong way round is the "
         "single commonest reason RTTY comes out as rubbish, and it is worth knowing that "
         "it is a one-click fix rather than a bad recording.\n\n"
         "Commercial and weather stations use 425 or 850 Hz shifts and other speeds; set "
         "them by hand if 170 does not decode."),
     tags=["rtty", "baudot", "ita2", "teleprinter", "radio", "ham", "fsk", "45 baud"],
     input_kind="file", input_label="Audio or video file", input_types=MEDIA_TYPES,
     params=[Param("baud", "Baud", "float", 45.45, minimum=10.0, maximum=1200.0,
                   help="45.45 is standard amateur. 50 and 75 turn up elsewhere."),
             Param("shift", "Shift (Hz)", "float", 170.0, minimum=20.0, maximum=2000.0,
                   help="170 amateur, 425 or 850 commercial and weather."),
             Param("centre", "Centre frequency (0 = find it)", "float", 0.0,
                   minimum=0.0, maximum=4000.0),
             Param("reverse", "Try reversed polarity first", "bool", False),
             Param("unshift_on_space", "Unshift on space", "bool", True,
                   help="Most stations return to letters after a space. Turn off if "
                        "figures are being lost.")],
     action=_rtty_decode, action_label="Decode")


tool(id="rtty-make", name="RTTY generator", category=CAT,
     summary="Turn text into a RTTY audio file",
     explain=(
         "Writes a WAV of your text sent as RTTY: a second of idle mark tone to let a "
         "receiver lock on, then the characters, each as a start bit, five data bits and "
         "a stop.\n\n"
         "Useful for testing a decoder - this one included - or for feeding into a "
         "transmitter's audio input. Play it back through the decoder and you should get "
         "your text out the other end."),
     tags=["rtty", "generate", "baudot", "wav", "transmit"],
     params=[Param("baud", "Baud", "float", 45.45, minimum=10.0, maximum=1200.0),
             Param("shift", "Shift (Hz)", "float", 170.0, minimum=20.0, maximum=2000.0),
             Param("centre", "Centre frequency", "float", 2210.0, minimum=300.0,
                   maximum=3500.0),
             Param("rate", "Sample rate", "int", 11025, minimum=8000, maximum=48000),
             Param("lead_in", "Idle before the text (s)", "float", 1.0,
                   minimum=0.0, maximum=10.0),
             Param("outdir", "Save into", "folder", "",
                   help="Blank saves it in your default save folder (File menu).")],
     action=_rtty_encode, action_label="Make WAV")


# --------------------------------------------------------------------------
# PSK31
# --------------------------------------------------------------------------
# Varicode: no character contains two adjacent zeros, so "00" is free to mean
# "end of character".  Frequent letters get short codes - 'e' is two bits.

VARICODE = ["1010101011", "1011011011", "1011101101", "1101110111",
    "1011101011", "1101011111", "1011101111", "1011111101", "1011111111",
    "11101111", "11101", "1101101111", "1011011101", "11111", "1101110101",
    "1110101011", "1011110111", "1011110101", "1110101101", "1110101111",
    "1101011011", "1101101011", "1101101101", "1101010111", "1101111011",
    "1101111101", "1110110111", "1101010101", "1101011101", "1110111011",
    "1011111011", "1101111111", "1", "111111111", "101011111", "111110101",
    "111011011", "1011010101", "1010111011", "101111111", "11111011",
    "11110111", "101101111", "111011111", "1110101", "110101", "1010111",
    "110101111", "10110111", "10111101", "11101101", "11111111", "101110111",
    "101011011", "101101011", "110101101", "110101011", "110110111",
    "11110101", "110111101", "111101101", "1010101", "111010111",
    "1010101111", "1010111101", "1111101", "11101011", "10101101",
    "10110101", "1110111", "11011011", "11111101", "101010101", "1111111",
    "111111101", "101111101", "11010111", "10111011", "11011101", "10101011",
    "11010101", "111011101", "10101111", "1101111", "1101101", "101010111",
    "110110101", "101011101", "101110101", "101111011", "1010101101",
    "111110111", "111101111", "111111011", "1010111111", "101101101",
    "1011011111", "1011", "1011111", "101111", "101101", "11", "111101",
    "1011011", "101011", "1101", "111101011", "10111111", "11011", "111011",
    "1111", "111", "111111", "110111111", "10101", "10111", "101", "110111",
    "1111011", "1101011", "11011111", "1011101", "111010101", "1010110111",
    "110111011", "1010110101", "1011010111", "1110110101"
]
VARI_TO_CHAR = {}
for _i, _code in enumerate(VARICODE):
    VARI_TO_CHAR.setdefault(_code, chr(_i))


def _psk_carrier(samples, rate):
    """Find a BPSK carrier by squaring the signal first.

    Phase reversals of half a turn become whole turns when squared, so the
    modulation cancels and what is left is a clean tone at twice the carrier.
    Looking for that is far more accurate than looking at the signal itself,
    whose energy is spread either side of the carrier and never sits on it.
    """
    np = _np()
    n = min(len(samples), 1 << 19)
    x = samples[:n].astype(np.float64)
    sq = (x * x) - (x * x).mean()
    mag = np.abs(np.fft.rfft(sq * np.hanning(sq.size)))
    freqs = np.fft.rfftfreq(sq.size, 1.0 / rate)
    band = (freqs > 200) & (freqs < 7000)
    if not band.any():
        return _strongest_tone(samples, rate)
    sub, sf = mag[band], freqs[band]
    k = int(np.argmax(sub))
    # parabolic interpolation between bins, for a fraction-of-a-hertz answer
    if 0 < k < sub.size - 1:
        a, b, c = sub[k - 1], sub[k], sub[k + 1]
        shift = 0.5 * (a - c) / (a - 2 * b + c + 1e-30)
    else:
        shift = 0.0
    return float((sf[k] + shift * (sf[1] - sf[0])) / 2.0)


def _psk_decode(path, carrier=0.0, baud=31.25, **_k):
    np = _np()
    samples, rate = load_audio(path)
    baud = float(clamp(baud, 5.0, 500.0, 31.25))
    if carrier <= 0:
        carrier = _psk_carrier(samples, rate)
    spb = rate / baud

    t = np.arange(len(samples)) / rate
    win = max(4, int(spb))
    base = np.convolve(samples.astype(np.float64) * np.exp(-2j * np.pi * carrier * t),
                       np.ones(win) / win, mode="same")

    # symbol timing: the envelope dips to nothing at every phase reversal, so
    # it carries a tone at the symbol rate and its phase is the clock
    env = np.abs(base)
    if env.max() <= 0:
        raise ToolError("That recording is silent.")
    k = np.arange(env.size)
    phase = np.angle(np.sum(env * np.exp(-2j * np.pi * k / spb))) / (2 * np.pi) * spb

    best = None
    for nudge in (0.0, 0.25, -0.25, 0.5):
        start = (phase + nudge * spb) % spb
        idx = np.arange(start, len(base) - 1, spb).astype(np.int64)
        idx = idx[(idx >= 0) & (idx < len(base))]
        if idx.size < 8:
            continue
        sym = base[idx]
        diff = sym[1:] * np.conj(sym[:-1])
        # any leftover frequency error turns up as a constant twist on every
        # symbol; squaring removes the data and leaves the twist to be undone
        twist = np.angle(np.mean(diff ** 2)) / 2.0
        bits = (np.real(diff * np.exp(-1j * twist)) > 0).astype(np.uint8)
        text, chars = _varicode_stream(bits)
        score = _printable(text) * min(1.0, chars / 4.0)
        if best is None or score > best[0]:
            best = (score, text, chars, twist)
    if best is None:
        raise ToolError("That recording is too short for PSK31.")
    score, text, chars, twist = best
    offset = twist * baud / (2 * np.pi)

    if not text.strip():
        return Result(warn="Nothing decoded. Check the carrier frequency - PSK31 is only "
                           "about 60 Hz wide, so being 50 Hz out is enough to miss it. "
                           "The spectrogram will show you exactly where it is.")
    return Result(text=text,
                  rows=[("Characters", chars), ("Carrier", f"{carrier:.1f} Hz"),
                        ("Tuning error", f"{offset:+.2f} Hz"),
                        ("Baud", f"{baud:g}"), ("Looks like text", f"{_printable(text):.0%}")],
                  headers=["", ""], prefer="text",
                  note=f"{chars} character(s) at {baud:g} baud on {carrier:.0f} Hz.",
                  warn=None if _printable(text) > 0.6 else
                       "The result does not read cleanly - the carrier frequency is "
                       "probably slightly off. Try setting it by hand.")


def _varicode_stream(bits):
    """Varicode has no character with two zeros in a row, so "00" is the gap
    between characters and no start or stop bits are needed."""
    out, run, chars, prev0 = [], "", 0, False
    for b in bits:
        if b:
            run += "1"
            prev0 = False
        elif prev0:
            code = run[:-1]          # drop the first of the two zeros
            if code:
                c = VARI_TO_CHAR.get(code)
                if c:
                    out.append(c)
                    chars += 1
            run, prev0 = "", False
        else:
            run += "0"
            prev0 = True
    if run.strip("0"):
        c = VARI_TO_CHAR.get(run.rstrip("0"))
        if c:
            out.append(c)
            chars += 1
    return "".join(out), chars


def _strongest_tone(samples, rate, lo=300.0, hi=3000.0):
    np = _np()
    n = min(len(samples), 1 << 17)
    seg = samples[:n] * np.hanning(n)
    mag = np.abs(np.fft.rfft(seg))
    freqs = np.fft.rfftfreq(n, 1.0 / rate)
    band = (freqs > lo) & (freqs < hi)
    if not band.any():
        return 1000.0
    sub = mag[band]
    return float(freqs[band][int(np.argmax(sub))])


def _psk_encode(data, carrier=1000.0, baud=31.25, rate=11025, lead_in=1.0, outdir=""):
    np = _np()
    text = to_text(data)
    if not text.strip():
        raise ToolError("Type something to send.")
    baud = float(clamp(baud, 5.0, 500.0, 31.25))
    rate = int(clamp(rate, 8000, 48000, 11025))
    carrier = float(clamp(carrier, 100.0, 4000.0, 1000.0))

    bits = []
    bits += [0] * int(baud * float(clamp(lead_in, 0.0, 10.0, 1.0)))   # idle: reversals
    for ch in text:
        code = VARICODE[ord(ch)] if ord(ch) < len(VARICODE) else VARICODE[ord("?")]
        bits += [1 if c == "1" else 0 for c in code]
        bits += [0, 0]
    bits += [0] * int(baud * 0.5)

    # A one holds the phase, a zero reverses it. The reversal is eased through
    # zero over one symbol - that shaping is what keeps PSK31 inside 60 Hz.
    pol, level = [], 1.0
    for b in bits:
        if not b:
            level = -level
        pol.append(level)
    steps = _stretch(pol, rate, baud)
    n = max(4, int(round(rate / baud)))
    kernel = np.hanning(n + 2)[1:-1]
    kernel = kernel / kernel.sum()
    baseband = np.convolve(steps, kernel, mode="same")
    t = np.arange(baseband.size) / rate
    audio = 0.7 * baseband * np.cos(2 * np.pi * carrier * t)

    dest = os.path.join(outdir or default_save_dir(), "psk31.wav")
    secs = _write_wav(dest, audio, rate)
    return Result(file_path=dest,
                  rows=[("Characters", len(text)), ("Carrier", f"{carrier:g} Hz"),
                        ("Baud", f"{baud:g}"), ("Length", f"{secs:.1f} s"),
                        ("Saved to", dest)],
                  headers=["", ""],
                  note=f"{secs:.1f} seconds written to {dest}.")


tool(id="psk31", name="PSK31", category=CAT,
     summary="Decode the narrow phase-shift mode used for keyboard-to-keyboard contacts",
     explain=(
         "PSK31 does not move the tone at all. It keeps one steady note and flips its "
         "phase - the point in the wave's cycle - by half a turn to send a zero, and "
         "leaves it alone to send a one. Done at 31.25 baud with the amplitude eased "
         "through each reversal, the whole signal fits in about 60 Hz, which is narrower "
         "than a human whisper and is why it gets through when nothing else will.\n\n"
         "The character set is varicode, and it is a neat piece of design: no character "
         "contains two zeros in a row, which frees up '00' to mean 'end of character' and "
         "removes the need for start and stop bits entirely. Common letters get short "
         "codes - 'e' is a single bit - so English runs at about 50 words a minute.\n\n"
         "Point it at a recording and it finds the carrier, recovers the timing from the "
         "dip in amplitude at every reversal, and reads it off. If it comes out as "
         "nonsense the carrier is usually a few tens of hertz out; the spectrogram will "
         "show you where the signal really is."),
     tags=["psk31", "bpsk", "varicode", "radio", "ham", "phase shift", "narrowband"],
     input_kind="file", input_label="Audio or video file", input_types=MEDIA_TYPES,
     params=[Param("carrier", "Carrier (0 = find it)", "float", 0.0, minimum=0.0,
                   maximum=4000.0),
             Param("baud", "Baud", "float", 31.25, minimum=5.0, maximum=500.0,
                   help="31.25 is PSK31. 62.5 is PSK63.")],
     action=_psk_decode, action_label="Decode")


tool(id="psk31-make", name="PSK31 generator", category=CAT,
     summary="Turn text into a PSK31 audio file",
     explain=(
         "Writes your text as PSK31: an idle preamble of continuous phase reversals so a "
         "receiver can find the timing, the characters in varicode, then a run of idle to "
         "close. The amplitude is eased to zero through every reversal, which is what "
         "keeps the signal narrow and stops it splattering across the band.\n\n"
         "Good for testing a decoder or feeding a transmitter."),
     tags=["psk31", "generate", "bpsk", "wav", "transmit"],
     params=[Param("carrier", "Carrier (Hz)", "float", 1000.0, minimum=100.0,
                   maximum=4000.0),
             Param("baud", "Baud", "float", 31.25, minimum=5.0, maximum=500.0),
             Param("rate", "Sample rate", "int", 11025, minimum=8000, maximum=48000),
             Param("lead_in", "Idle before the text (s)", "float", 1.0, minimum=0.0,
                   maximum=10.0),
             Param("outdir", "Save into", "folder", "",
                   help="Blank saves it in your default save folder (File menu).")],
     action=_psk_encode, action_label="Make WAV")


# --------------------------------------------------------------------------
# AX.25 packet / APRS
# --------------------------------------------------------------------------

def _crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def _ax25_frames(bits):
    """Pull frames out of an HDLC bit stream.

    01111110 is the flag that marks a frame's edges, and to stop that pattern
    ever appearing inside one the transmitter stuffs a 0 after any five 1s in
    a row. So: find the flags, take what is between two of them, drop every
    stuffed bit, and read the rest off eight at a time, least significant bit
    first.
    """
    flags, window = [], 0
    for i, b in enumerate(bits):
        window = ((window << 1) | int(b)) & 0xFF
        if window == 0x7E:
            flags.append(i)
    frames = []
    for a, b in zip(flags, flags[1:]):
        seg = bits[a + 1:b - 7]
        if len(seg) < 140 or len(seg) > 4000:
            continue
        out, ones, ok = [], 0, True
        for bit in seg:
            bit = int(bit)
            if ones == 5:
                ones = 0
                if bit == 0:
                    continue          # a stuffed bit - throw it away
                ok = False            # seven 1s in a row: an abort, not a frame
                break
            out.append(bit)
            ones = ones + 1 if bit else 0
        if not ok or len(out) < 136:
            continue
        data = bytearray()
        for k in range(len(out) // 8):
            value = 0
            for j in range(8):
                value |= out[k * 8 + j] << j
            data.append(value)
        frames.append(bytes(data))
    return frames


def _ax25_decode_frame(frame: bytes):
    if len(frame) < 17:
        return None
    body, crc = frame[:-2], frame[-2] | (frame[-1] << 8)
    good = _crc16_ccitt(body) == crc
    addrs, p = [], 0
    while p + 7 <= len(body):
        block = body[p:p + 7]
        call = "".join(chr(c >> 1) for c in block[:6]).strip()
        ssid = (block[6] >> 1) & 0x0F
        addrs.append(call + (f"-{ssid}" if ssid else ""))
        p += 7
        if block[6] & 1:
            break
        if len(addrs) > 10:
            return None
    if len(addrs) < 2 or p + 2 > len(body):
        return None
    ctrl, pid = body[p], body[p + 1]
    info = body[p + 2:]
    return {"to": addrs[0], "from": addrs[1], "via": addrs[2:],
            "ctrl": ctrl, "pid": pid, "crc_ok": good,
            "info": info.decode("latin-1", "replace")}


def _aprs_meaning(info: str) -> str:
    """Read an APRS payload far enough to say what it is in plain words."""
    if not info:
        return ""
    kind = info[0]
    names = {"!": "position, no timestamp", "=": "position with messaging",
             "@": "position with timestamp", "/": "position with timestamp",
             ">": "status", ":": "message", ";": "object", ")": "item",
             "`": "Mic-E position", "'": "Mic-E position", "T": "telemetry",
             "_": "weather report", "$": "raw NMEA"}
    what = names.get(kind, "")
    body = info[1:]
    if kind in "@/":
        body = body[7:]                      # skip the timestamp
    if kind in "!=@/":
        import re
        m = re.match(r"(\d{2})(\d{2}\.\d{2})([NS])(.)(\d{3})(\d{2}\.\d{2})([EW])(.)",
                     body)
        if m:
            lat = (int(m.group(1)) + float(m.group(2)) / 60) * \
                (-1 if m.group(3) == "S" else 1)
            lon = (int(m.group(5)) + float(m.group(6)) / 60) * \
                (-1 if m.group(7) == "W" else 1)
            rest = body[m.end():].strip()
            what += f" - {lat:.5f}, {lon:.5f}"
            if rest:
                what += f'  "{rest[:40]}"'
    elif kind == ":" and len(body) > 9:
        what += f" to {body[:9].strip()}: {body[10:][:40]}"
    elif kind == ">":
        what += f': "{body[:50]}"'
    return what


def _aprs_decode(path, mark=1200.0, space=2200.0, baud=1200.0):
    np = _np()
    samples, rate = load_audio(path)
    baud = float(clamp(baud, 100.0, 9600.0, 1200.0))
    track, _win = _tone_track(samples, rate, float(mark), float(space), baud)

    rows, seen = [], []
    for inv in (False, True):
        bits, _idx = _clock(track, rate, baud, invert=inv)
        # NRZI: no change means 1, a change means 0
        nrz = np.concatenate([[1], (np.diff(bits.astype(np.int8)) == 0).astype(np.uint8)])
        for frame in _ax25_frames(nrz):
            got = _ax25_decode_frame(frame)
            if got and got not in seen:
                seen.append(got)
        if seen:
            break

    if not seen:
        return Result(warn="No packets found. Check it really is 1200 baud AFSK - packet "
                           "sounds like a short harsh buzz, about half a second long, "
                           "quite unlike RTTY's warble. The spectrogram will show two "
                           "tones at 1200 and 2200 Hz.")
    lines = []
    for f in seen:
        path_s = ",".join(f["via"]) if f["via"] else ""
        head = f"{f['from']}>{f['to']}" + (f",{path_s}" if path_s else "")
        lines.append(f"{head}:{f['info']}")
        meaning = _aprs_meaning(f["info"])
        rows.append((f["from"], f["to"], ("ok" if f["crc_ok"] else "BAD CRC"),
                     meaning or f["info"][:60]))
    bad = sum(1 for f in seen if not f["crc_ok"])
    return Result(text="\n".join(lines), rows=rows,
                  headers=["From", "To", "CRC", "What it says"], prefer="text",
                  note=f"{len(seen)} frame(s) decoded"
                       + (f", {bad} with a bad checksum." if bad else ", all checksums good."),
                  warn=None if not bad else
                       "Some frames failed their checksum, so parts of them are wrong. "
                       "That is normal on a weak or clipped recording.")


def _aprs_encode(data, source="N0CALL", dest="APRS", via="WIDE1-1", mark=1200.0,
                 space=2200.0, baud=1200.0, rate=22050, outdir=""):
    np = _np()
    info = to_text(data)
    if not info.strip():
        raise ToolError("Type the payload to send - for APRS, a status or position report.")

    def addr(call, last):
        call = call.upper().strip()
        ssid = 0
        if "-" in call:
            call, _, s = call.partition("-")
            ssid = int(s) if s.isdigit() else 0
        if not call or len(call) > 6 or not call.isalnum():
            raise ToolError(f"{call!r} is not a valid callsign - up to six letters "
                            "and digits, optionally -0 to -15.")
        out = bytearray((ord(c) << 1) for c in call.ljust(6))
        out.append(0x60 | ((ssid & 0x0F) << 1) | (1 if last else 0))
        return bytes(out)

    vias = [v for v in via.replace(",", " ").split() if v.strip()]
    body = addr(dest, False) + addr(source, not vias)
    for i, v in enumerate(vias):
        body += addr(v, i == len(vias) - 1)
    body += bytes([0x03, 0xF0]) + info.encode("latin-1", "replace")
    crc = _crc16_ccitt(body)
    frame = body + bytes([crc & 0xFF, crc >> 8])

    bits = []
    for byte in frame:
        for k in range(8):
            bits.append((byte >> k) & 1)
    # bit stuffing, then flags either side
    stuffed, ones = [], 0
    for b in bits:
        stuffed.append(b)
        ones = ones + 1 if b else 0
        if ones == 5:
            stuffed.append(0)
            ones = 0
    flag = [0, 1, 1, 1, 1, 1, 1, 0]
    stream = flag * 16 + stuffed + flag * 4

    # NRZI: a zero flips the tone, a one holds it
    level, syms = 1, []
    for b in stream:
        if not b:
            level ^= 1
        syms.append(mark if level else space)

    rate = int(clamp(rate, 8000, 48000, 22050))
    freq = _stretch(syms, rate, baud)
    phase = np.cumsum(2 * np.pi * freq / rate)
    audio = 0.7 * np.sin(phase)
    dest_path = os.path.join(outdir or default_save_dir(), "packet.wav")
    secs = _write_wav(dest_path, audio, rate)
    return Result(file_path=dest_path,
                  rows=[("From", source), ("To", dest), ("Path", ",".join(vias) or "(none)"),
                        ("Payload", info[:60]), ("Frame", f"{len(frame)} bytes"),
                        ("CRC", f"{crc:04X}"), ("Length", f"{secs:.2f} s"),
                        ("Saved to", dest_path)],
                  headers=["", ""],
                  note=f"{secs:.2f} seconds written to {dest_path}.")


tool(id="aprs", name="Packet radio / APRS (AX.25)", category=CAT,
     summary="Decode 1200 baud AFSK packets - callsigns, path and payload",
     explain=(
         "The short harsh buzz on 144.800 (or 144.390 in the States) is AX.25 packet, and "
         "under it is a proper network protocol rather than a stream of characters. Every "
         "frame carries who sent it, who it is for, the list of digipeaters it should be "
         "relayed through, a payload, and a checksum - so unlike RTTY or PSK you can tell "
         "whether what you decoded is right.\n\n"
         "The signalling is Bell 202: 1200 Hz for one state, 2200 Hz for the other, 1200 "
         "baud, exactly as 1970s telephone modems worked. On top of that sits HDLC, which "
         "marks frames with 01111110 and stuffs a zero after any five ones so that pattern "
         "can never appear inside one.\n\n"
         "APRS is what most of that traffic is: position beacons, weather stations, "
         "messages. A payload starting with ! or = is a position, @ or / adds a "
         "timestamp, > is a status.\n\n"
         "Feed it a recording off a scanner or an SDR and it will list every frame it "
         "finds, with the checksum result beside each one."),
     tags=["aprs", "ax25", "packet", "afsk", "bell 202", "1200 baud", "radio", "ham"],
     input_kind="file", input_label="Audio or video file", input_types=MEDIA_TYPES,
     params=[Param("mark", "Mark tone (Hz)", "float", 1200.0, minimum=300.0, maximum=4000.0),
             Param("space", "Space tone (Hz)", "float", 2200.0, minimum=300.0,
                   maximum=4000.0),
             Param("baud", "Baud", "float", 1200.0, minimum=100.0, maximum=9600.0,
                   help="1200 on VHF. 300 baud packet on HF uses 200 Hz shift instead.")],
     action=_aprs_decode, action_label="Decode packets")


tool(id="aprs-make", name="APRS packet generator", category=CAT,
     summary="Build a valid AX.25 frame and write it as audio",
     explain=(
         "Assembles a real AX.25 frame - addresses encoded the way the protocol wants "
         "them, control and protocol bytes, your payload, a CRC over the lot - then wraps "
         "it in HDLC framing with proper bit stuffing and writes it out as Bell 202 audio.\n\n"
         "The result decodes in any packet software, which makes it the right way to test "
         "a TNC, a decoder or a receive setup without needing anything on the air.\n\n"
         "Do not transmit it unless you hold a licence and the callsign is yours."),
     tags=["aprs", "ax25", "packet", "generate", "afsk", "tnc", "wav"],
     params=[Param("source", "From (your callsign)", "text", "N0CALL", width=12),
             Param("dest", "To", "text", "APRS", width=12),
             Param("via", "Digipeater path", "text", "WIDE1-1", width=16),
             Param("mark", "Mark tone (Hz)", "float", 1200.0, minimum=300.0, maximum=4000.0),
             Param("space", "Space tone (Hz)", "float", 2200.0, minimum=300.0, maximum=4000.0),
             Param("baud", "Baud", "float", 1200.0, minimum=100.0, maximum=9600.0),
             Param("rate", "Sample rate", "int", 22050, minimum=8000, maximum=48000),
             Param("outdir", "Save into", "folder", "",
                   help="Blank saves it in your default save folder (File menu).")],
     action=_aprs_encode, action_label="Make WAV")
