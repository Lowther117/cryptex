"""Signals — sound that carries a picture or a message.

The slow-scan (SSTV) decoder is the centrepiece: an amateur-radio picture
transmission is an audio tone whose *frequency* is the brightness of the pixel
being drawn, one line at a time. Feed it a WAV recording and it draws the
picture back.
"""
from __future__ import annotations

import math
import os
import struct
import wave

from .core import (Param, Result, ToolError, clamp, need, to_text, tool)

CAT = "Signals"

BLACK, WHITE = 1500.0, 2300.0
SYNC = 1200.0


def _np():
    try:
        import numpy as np
    except ImportError as exc:
        raise ToolError("This tool needs numpy. Run: pip install numpy "
                        "(the build scripts install it for you).") from exc
    return np


# --------------------------------------------------------------------------
# Audio loading
# --------------------------------------------------------------------------

def read_wav(path):
    """Plain PCM WAV only: (float32 samples in -1..1, sample rate)."""
    np = _np()
    with wave.open(path, "rb") as w:
        nch, width, rate, n = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
        raw = w.readframes(n)
    if width == 1:
        data = (np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128.0) / 128.0
    elif width == 2:
        data = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0
    elif width == 3:
        b = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 3).astype(np.int32)
        v = (b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16))
        v = np.where(v & 0x800000, v - (1 << 24), v)
        data = v.astype(np.float32) / 8388608.0
    elif width == 4:
        data = np.frombuffer(raw, dtype="<i4").astype(np.float32) / 2147483648.0
    else:
        raise ToolError(f"Unsupported sample width: {width * 8} bits.")
    if nch > 1:
        data = data.reshape(-1, nch).mean(axis=1)
    if data.size == 0:
        raise ToolError("That file contains no audio.")
    return data.astype(np.float32), rate


def load_audio(path):
    """Any audio or video file as (float32 mono samples, sample rate).

    Plain WAV is read directly; everything else - mp4, mkv, mov, mp3, m4a,
    flac, ogg, a WAV in a compressed format - is handed to ffmpeg first.
    """
    from .audio import Media
    _np()
    path = need(path, "Pick an audio or video file.")
    if not os.path.isfile(path):
        raise ToolError(f"Not a file: {path}")
    with Media(path) as wav:
        return read_wav(wav)


MEDIA_TYPES = [("Audio and video", "*.wav *.mp3 *.m4a *.aac *.flac *.ogg *.opus *.aiff "
                                   "*.wma *.mp4 *.m4v *.mov *.mkv *.avi *.webm *.ts *.mpg"),
               ("All files", "*.*")]


def _analytic(x):
    """Analytic signal of one block via FFT (the standard Hilbert construction)."""
    np = _np()
    n = x.size
    spec = np.fft.fft(x)
    h = np.zeros(n)
    h[0] = 1.0
    if n % 2 == 0:
        h[n // 2] = 1.0
        h[1:n // 2] = 2.0
    else:
        h[1:(n + 1) // 2] = 2.0
    return np.fft.ifft(spec * h)


def instantaneous_frequency(samples, rate, block=1 << 20, overlap=4096):
    """FM demodulation. Returns a frequency in Hz for every sample.

    The analytic signal (the original plus a 90-degree-shifted copy) turns the
    waveform into a rotating vector; how fast it rotates from one sample to the
    next IS the instantaneous frequency, which for SSTV is the pixel value.

    Done in overlapping blocks so a long recording does not need an FFT of the
    whole file, and the wrap-around error at each block edge is thrown away.
    """
    np = _np()
    x = (samples - samples.mean()).astype(np.float64)
    n = x.size
    out = np.empty(n, dtype=np.float32)
    if n <= block:
        phase = np.unwrap(np.angle(_analytic(x)))
        f = np.diff(phase) * rate / (2.0 * np.pi)
        out[:] = np.concatenate([f[:1], f])
        return np.clip(out, 0.0, 4000.0)
    step = block - 2 * overlap
    pos = 0
    while pos < n:
        a = max(0, pos - overlap)
        b = min(n, pos + step + overlap)
        seg = x[a:b]
        phase = np.unwrap(np.angle(_analytic(seg)))
        f = np.diff(phase) * rate / (2.0 * np.pi)
        f = np.concatenate([f[:1], f])
        lo = pos - a
        hi = lo + min(step, n - pos)
        out[pos:pos + (hi - lo)] = f[lo:hi]
        pos += step
    return np.clip(out, 0.0, 4000.0)


def _smooth(a, win):
    np = _np()
    if win < 2:
        return a
    k = np.ones(win, dtype=np.float32) / win
    return np.convolve(a, k, mode="same")


# --------------------------------------------------------------------------
# SSTV mode table
# --------------------------------------------------------------------------
# Times in milliseconds. `layout` is the sequence of segments in one
# transmitted line: ("sync", ms) | ("gap", ms, hz) | ("scan", ms, channel)

class Mode:
    def __init__(self, name, vis, width, lines, layout, colour, line_ms=None,
                 two_rows=False, start_sync=0.0):
        self.name, self.vis, self.width, self.lines = name, vis, width, lines
        self.layout, self.colour, self.two_rows = layout, colour, two_rows
        self.start_sync = start_sync      # extra pulse sent once, before line 0
        self.line_ms = line_ms or sum(seg[1] for seg in layout)

    def sync_offset(self):
        """Where the sync pulse sits inside a line. Scottie puts it two thirds in."""
        t = 0.0
        for seg in self.layout:
            if seg[0] == "sync":
                return t
            t += seg[1]
        return 0.0

    def scans(self):
        return [seg for seg in self.layout if seg[0] == "scan"]


def _martin(name, vis, pixel_ms, lines=256):
    scan = pixel_ms * 320
    return Mode(name, vis, 320, lines,
                [("sync", 4.862), ("gap", 0.572, 1500.0),
                 ("scan", scan, "G"), ("gap", 0.572, 1500.0),
                 ("scan", scan, "B"), ("gap", 0.572, 1500.0),
                 ("scan", scan, "R"), ("gap", 0.572, 1500.0)],
                "GBR")


def _scottie(name, vis, pixel_ms, lines=256):
    scan = pixel_ms * 320
    return Mode(name, vis, 320, lines,
                [("gap", 1.5, 1500.0), ("scan", scan, "G"),
                 ("gap", 1.5, 1500.0), ("scan", scan, "B"),
                 ("sync", 9.0), ("gap", 1.5, 1500.0), ("scan", scan, "R")],
                "GBR", start_sync=9.0)


def _pd(name, vis, pixel_ms, width=320, rows=256):
    # PD sends TWO picture rows per transmitted line, so the line count is half
    scan = pixel_ms * width
    return Mode(name, vis, width, rows // 2,
                [("sync", 20.0), ("gap", 2.08, 1500.0),
                 ("scan", scan, "Y0"), ("scan", scan, "RY"),
                 ("scan", scan, "BY"), ("scan", scan, "Y1")],
                "YCrCb", two_rows=True)


MODES = {}
for _m in [
    _martin("Martin M1", 44, 0.4576),
    _martin("Martin M2", 40, 0.2288),
    _martin("Martin M3", 36, 0.4576, lines=128),
    _martin("Martin M4", 32, 0.2288, lines=128),
    _scottie("Scottie S1", 60, 0.4320),
    _scottie("Scottie S2", 56, 0.2752),
    _scottie("Scottie S3", 52, 0.4320, lines=128),
    _scottie("Scottie S4", 48, 0.2752, lines=128),
    _scottie("Scottie DX", 76, 1.0800),
    Mode("Wraase SC2-180", 55, 320, 256,
         [("sync", 5.5225), ("gap", 0.5, 1500.0),
          ("scan", 235.0, "R"), ("scan", 235.0, "G"), ("scan", 235.0, "B")],
         "RGB"),
    Mode("Robot 36", 8, 320, 240,
         [("sync", 9.0), ("gap", 3.0, 1500.0), ("scan", 88.0, "Y"),
          ("gap", 4.5, 1500.0), ("gap", 1.5, 1900.0), ("scan", 44.0, "C")],
         "R36"),
    Mode("Robot 72", 12, 320, 240,
         [("sync", 9.0), ("gap", 3.0, 1500.0), ("scan", 138.0, "Y"),
          ("gap", 4.5, 1500.0), ("gap", 1.5, 1900.0), ("scan", 69.0, "RY"),
          ("gap", 4.5, 2300.0), ("gap", 1.5, 1900.0), ("scan", 69.0, "BY")],
         "YCrCb422"),
    _pd("PD50", 93, 0.286),
    _pd("PD90", 99, 0.532),
    _pd("PD120", 95, 0.190, 640, 496),
    _pd("PD160", 98, 0.382, 512, 400),
    _pd("PD180", 96, 0.286, 640, 496),
    _pd("PD240", 97, 0.382, 640, 496),
    _pd("PD290", 94, 0.286, 800, 616),
]:
    MODES[_m.name] = _m

VIS_TO_MODE = {m.vis: m for m in MODES.values()}


# --------------------------------------------------------------------------
# VIS header
# --------------------------------------------------------------------------

def find_vis(freq, rate):
    """Locate the VIS header and return (mode, sample index just after it).

    The header is: 1900 Hz for 300 ms, 1200 Hz for 10 ms, 1900 Hz for 300 ms,
    then a 30 ms start bit at 1200 Hz, eight 30 ms data bits (1100 = 1,
    1300 = 0, least significant first, the last being an even parity bit),
    and a 30 ms stop bit at 1200 Hz.
    """
    np = _np()
    rate = int(round(rate))
    step = max(1, rate // 1000)                      # one point per millisecond
    coarse = freq[:len(freq) // step * step].reshape(-1, step).mean(axis=1)
    n = len(coarse)

    def near(a, hz, tol=80.0):
        return np.abs(a - hz) < tol

    best = None
    i = 0
    while i < n - 1000:
        # a 300 ms run at 1900 Hz, allowing for noise
        win = coarse[i:i + 300]
        if near(win, 1900.0).mean() > 0.75:
            j = i + 300
            # skip to the start bit: the next solid 1200 Hz run of ~30 ms
            k = j
            limit = min(n - 330, j + 400)
            while k < limit:
                if near(coarse[k:k + 25], SYNC, 90.0).mean() > 0.8:
                    # walk back to the exact edge - the 80%-of-25ms test can
                    # trigger a few milliseconds into the start bit, and every
                    # millisecond here is most of a pixel later on
                    edge = k
                    while edge > 0 and near(coarse[edge - 1:edge], SYNC, 120.0).all():
                        edge -= 1
                    k = edge
                    bit_start = k + 30
                    bits = []
                    ok = True
                    for b in range(8):
                        seg = coarse[bit_start + b * 30 + 6: bit_start + b * 30 + 24]
                        if seg.size == 0:
                            ok = False
                            break
                        f = float(np.median(seg))
                        if abs(f - 1100.0) < 110:
                            bits.append(1)
                        elif abs(f - 1300.0) < 110:
                            bits.append(0)
                        else:
                            ok = False
                            break
                    if ok:
                        code = sum(b << idx for idx, b in enumerate(bits[:7]))
                        parity_ok = (sum(bits[:7]) % 2) == bits[7]
                        mode = VIS_TO_MODE.get(code)
                        end = (bit_start + 8 * 30 + 30) * step
                        if mode:
                            return mode, end, code, parity_ok
                        if best is None:
                            best = (None, end, code, parity_ok)
                    k += 1
                else:
                    k += 1
            i = j
        else:
            i += 10
    if best:
        return best
    return None, 0, None, False


# --------------------------------------------------------------------------
# Decoder
# --------------------------------------------------------------------------

def _find_syncs(freq, rate, mode, start, count):
    """Locate each line's sync pulse, then straighten the picture.

    A recording made through a sound card is never at exactly the rate it
    claims, so the picture slants. Fitting a straight line through the sync
    positions recovers the true line duration and removes the slant.
    """
    np = _np()
    sync_len = next((s[1] for s in mode.layout if s[0] == "sync"), 9.0)
    win = max(4, int(rate * sync_len / 1000.0))
    is_sync = (freq < 1350.0).astype(np.float32)
    energy = np.convolve(is_sync, np.ones(win, dtype=np.float32), mode="same")
    line_samples = mode.line_ms * rate / 1000.0
    # where to LOOK for line i's pulse (Scottie sends one extra pulse up front)
    search_off = (mode.start_sync + mode.sync_offset()) * rate / 1000.0
    # how far the pulse sits INTO its own line, which is what turns a measured
    # pulse position back into the start of that line
    line_off = mode.sync_offset() * rate / 1000.0
    is_sync = (freq < 1350.0).astype(np.float32)
    energy = np.convolve(is_sync, np.ones(win, dtype=np.float32), mode="same")

    def sweep(origin0, step0):
        tol = int(step0 * 0.08)
        found = []
        for i in range(count):
            centre = int(origin0 + i * step0)
            lo, hi = max(0, centre - tol), min(len(energy), centre + tol)
            if hi - lo < win:
                break
            seg = energy[lo:hi]
            peak = int(np.argmax(seg))
            if seg[peak] > win * 0.55:
                # the boxcar peaks when it is CENTRED on the pulse, so step back
                # half a pulse to get the moment the line actually starts
                found.append((i, lo + peak - win / 2.0))
        return found

    def fit(found):
        xs = np.array([f[0] for f in found], dtype=np.float64)
        ys = np.array([f[1] for f in found], dtype=np.float64)
        slope, intercept = np.polyfit(xs, ys, 1)
        resid = ys - (slope * xs + intercept)
        keep = np.abs(resid) < max(win, 3 * resid.std() + 1)
        if keep.sum() >= 8:
            slope, intercept = np.polyfit(xs[keep], ys[keep], 1)
        return float(slope), float(intercept)

    found = sweep(start + search_off, line_samples)
    if len(found) < 8:
        return line_samples, float(start) + mode.start_sync * rate / 1000.0, len(found)
    slope, intercept = fit(found)
    # Second pass: a recording whose clock is 0.1% out drifts further than the
    # search window by the bottom of the picture, so re-sweep using the line
    # duration we just measured and pick up the lines the first pass lost.
    found2 = sweep(intercept, slope)
    if len(found2) > len(found):
        found = found2
        slope, intercept = fit(found)
    return slope, intercept - line_off, len(found)


def scan_offsets(mode):
    """[(segment, milliseconds from the start of the line)] for every segment."""
    out, t = [], 0.0
    for seg in mode.layout:
        out.append((seg, t))
        t += seg[1]
    return out


def sample_line(freq, mode, line_start, rate, chans, row, offset_table=None):
    """Read one transmitted line out of the frequency stream into the colour
    planes. Shared by the file decoder and the live decoder so both behave
    identically."""
    np = _np()
    scale = 255.0 / (WHITE - BLACK)
    width = mode.width
    for seg, off in (offset_table or scan_offsets(mode)):
        if seg[0] != "scan":
            continue
        seg_start = line_start + off * rate / 1000.0
        seg_len = seg[1] * rate / 1000.0
        idx = seg_start + (np.arange(width) + 0.5) * (seg_len / width)
        i0 = np.clip(idx.astype(np.int64), 0, len(freq) - 2)
        frac = np.clip(idx - i0, 0.0, 1.0).astype(np.float32)
        vals = freq[i0] * (1 - frac) + freq[i0 + 1] * frac
        chans[seg[2]][row] = np.clip((vals - BLACK) * scale, 0, 255)


def decode_sstv(path, mode_name="auto", slant_ppm=0.0, start_ms=0.0, out_path=None,
                denoise=True, out_dir=""):
    np = _np()
    try:
        from PIL import Image
    except ImportError as exc:
        raise ToolError("This tool needs Pillow. Run: pip install pillow") from exc

    samples, rate = load_audio(path)
    freq = instantaneous_frequency(samples, rate)
    if denoise:
        freq = _smooth(freq, max(3, rate // 8000))

    vis_code, parity_ok = None, None
    if mode_name == "auto":
        mode, start, vis_code, parity_ok = find_vis(freq, rate)
        if mode is None:
            raise ToolError(
                "No SSTV header found."
                + (f" A VIS code of {vis_code} was seen but Cryptex does not know that mode."
                   if vis_code is not None else
                   " Check the recording actually contains an SSTV transmission, that it is not"
                   " clipped, and try again with the mode chosen by hand.")
                + " You can also set the mode manually and give a start offset in ms.")
    else:
        mode = MODES[mode_name]
        _m, vstart, vis_code, parity_ok = find_vis(freq, rate)
        start = int(start_ms * rate / 1000.0) if start_ms else (vstart or 0)

    if slant_ppm:
        rate_eff = rate * (1.0 + slant_ppm / 1e6)
    else:
        rate_eff = rate

    line_samples, origin, nsync = _find_syncs(freq, rate_eff, mode, start, mode.lines)
    width = mode.width
    rows = mode.lines
    img_rows = rows
    chans = {}
    for seg in mode.scans():
        chans[seg[2]] = np.zeros((rows, width), dtype=np.float32)

    for line in range(rows):
        sample_line(freq, mode, origin + line * line_samples, rate_eff, chans, line)

    img = _assemble(mode, chans, np)
    pil = Image.fromarray(img, "RGB")
    out_path = out_path or os.path.join(
        out_dir or os.path.dirname(os.path.abspath(path)),
        os.path.splitext(os.path.basename(path))[0] + f" [{mode.name}].png")
    pil.save(out_path)
    note = (f"{mode.name}: {pil.width}x{pil.height}. "
            f"{nsync} of {rows} sync pulses located; "
            f"line time measured at {line_samples*1000.0/rate:.3f} ms "
            f"(nominal {mode.line_ms:.3f} ms).")
    warn = ""
    if vis_code is not None and parity_ok is False:
        warn = "The VIS header failed its parity check — the mode may be wrong."
    if nsync < rows * 0.5:
        warn = (warn + " Few sync pulses were found, so the picture may be slanted or torn. "
                       "Try turning denoise off, or set the mode by hand.").strip()
    return pil, out_path, note, warn, mode


def _assemble(mode, chans, np):
    w = mode.width
    if mode.colour in ("GBR", "RGB"):
        rgb = np.stack([chans["R"], chans["G"], chans["B"]], axis=-1)
        return rgb.astype(np.uint8)
    if mode.colour == "R36":
        # 4:2:0 — chroma alternates R-Y, B-Y line by line, each shared by two lines
        y = chans["Y"]
        c = chans["C"]
        rows = y.shape[0]
        ry = np.zeros_like(y)
        by = np.zeros_like(y)
        for i in range(rows):
            if i % 2 == 0:
                ry[i] = c[i]
                by[i] = c[min(i + 1, rows - 1)]
            else:
                ry[i] = c[i - 1]
                by[i] = c[i]
        return _ycrcb(y, ry, by, np)
    if mode.colour == "YCrCb422":
        return _ycrcb(chans["Y"], chans["RY"], chans["BY"], np)
    # PD: each transmitted line carries two picture rows
    y0, y1 = chans["Y0"], chans["Y1"]
    ry, by = chans["RY"], chans["BY"]
    rows = y0.shape[0]
    out = np.zeros((rows * 2, w, 3), dtype=np.uint8)
    out[0::2] = _ycrcb(y0, ry, by, np)
    out[1::2] = _ycrcb(y1, ry, by, np)
    return out


def _ycrcb(y, ry, by, np):
    """Convert the SSTV Y / R-Y / B-Y planes to RGB.

    Robot and PD modes send studio-range YCbCr (Y 16-235, chroma 16-240) with
    the whole 0-255 scale mapped across the 1500-2300 Hz sweep, so the planes
    arrive already in those units - no second rescaling.
    """
    r = 1.164 * (y - 16.0) + 1.596 * (ry - 128.0)
    g = 1.164 * (y - 16.0) - 0.813 * (ry - 128.0) - 0.392 * (by - 128.0)
    b = 1.164 * (y - 16.0) + 2.017 * (by - 128.0)
    return np.clip(np.stack([r, g, b], axis=-1), 0, 255).astype(np.uint8)


tool(id="sstv-decode", name="Slow-scan (SSTV) decoder", category=CAT,
     summary="Turn a recorded radio transmission back into the picture",
     explain=(
         "Slow-scan television is how amateur radio operators send still pictures over a "
         "voice channel. The transmitter sweeps an audio tone between 1500 Hz (black) and "
         "2300 Hz (white), one pixel at a time, with a 1200 Hz pulse at the start of every "
         "line to keep the receiver in step. A single picture takes one to four minutes, "
         "which is where the name comes from.\n\n"
         "Feed this a WAV recording — off the radio, off a scanner, off a video, off the ISS "
         "downlink on 145.800 MHz — and it reads the header that says which mode was used, "
         "follows the sync pulses, measures the true line timing (which corrects the slant "
         "you get when your sound card's clock is slightly off), and redraws the picture.\n\n"
         "Modes understood: Martin M1-M4, Scottie S1-S4 and DX, Wraase SC2-180, Robot 36/72 "
         "and the PD family (PD50 to PD290) - nineteen in all. "
         "If the header is missing or corrupt you can name the mode yourself and nudge the "
         "start offset until the picture lines up.\n\n"
         "Any audio or video file works - wav, mp3, m4a, flac, ogg, mp4, mkv, mov. Anything "
         "that is not already plain WAV is converted with the bundled ffmpeg first, so a "
         "video you recorded off a screen is as good a source as a clean off-air WAV.\n\n"
         "To decode a transmission as it arrives instead, use 'Listen and decode (live)'."),
     tags=["sstv", "slow scan", "slowscan", "ham", "radio", "martin", "scottie", "robot",
           "wav", "picture", "iss", "amateur"],
     input_kind="file", input_label="Audio or video file", input_types=MEDIA_TYPES,
     params=[Param("mode", "Mode", "choice", "auto", choices=["auto"] + list(MODES)),
             Param("start_ms", "Start offset (ms)", "float", 0.0,
                   visible_when=lambda v: v.get("mode", "auto") != "auto",
                   help="Nudge this until the picture squares up."),
             Param("slant_ppm", "Slant correction (ppm)", "float", 0.0,
                   help="Leave at 0 — the decoder measures the slant itself from the sync pulses."),
             Param("denoise", "Smooth the signal", "bool", True,
                   help="Helps a noisy off-air recording; turn off for a clean file."),
             Param("outdir", "Save picture into", "folder", "")],
     action=lambda path, mode="auto", start_ms=0.0, slant_ppm=0.0, denoise=True, outdir="":
         _sstv_decode_tool(path, mode, float(start_ms), float(slant_ppm), denoise, outdir),
     action_label="Decode picture")


def _sstv_decode_tool(path, mode, start_ms, slant_ppm, denoise, outdir=""):
    pil, out, note, warn, m = decode_sstv(path, mode, slant_ppm, start_ms, None, denoise, outdir)
    return Result(image_path=out, file_path=out, note=note, warn=warn,
                  rows=[("Mode", m.name), ("VIS code", m.vis),
                        ("Picture", f"{pil.width} x {pil.height}"),
                        ("Nominal line time", f"{m.line_ms:.3f} ms"),
                        ("Saved to", out)],
                  headers=["", ""])


# --------------------------------------------------------------------------
# Encoder
# --------------------------------------------------------------------------

def encode_sstv(image_path, mode_name="Martin M1", rate=44100, out_path=None, out_dir=""):
    np = _np()
    try:
        from PIL import Image
    except ImportError as exc:
        raise ToolError("This tool needs Pillow.") from exc
    mode = MODES[mode_name]
    image_path = need(image_path, "Pick an image.")
    if not os.path.isfile(image_path):
        raise ToolError(f"Not a file: {image_path}")
    try:
        img = Image.open(image_path).convert("RGB")
    except Exception as exc:
        raise ToolError(f"That is not an image Cryptex can read ({exc}). "
                        "PNG, JPEG, GIF, BMP, WebP and TIFF all work.") from exc
    rows = mode.lines * (2 if mode.two_rows else 1)
    img = img.resize((mode.width, rows), Image.LANCZOS)
    arr = np.asarray(img).astype(np.float32)

    pieces = []
    clock = {"ms": 0.0, "n": 0}

    def _count(ms):
        """Samples for this segment, keeping the running total exact so a
        thousand roundings do not drift the line timing."""
        clock["ms"] += ms
        want = int(round(clock["ms"] * rate / 1000.0))
        n = max(1, want - clock["n"])
        clock["n"] += n
        return n

    def tone(hz, ms):
        pieces.append(np.full(_count(ms), float(hz), dtype=np.float64))

    def sweep(values, ms):
        n = _count(ms)
        idx = np.minimum((np.arange(n) * len(values) // n), len(values) - 1)
        pieces.append(BLACK + np.clip(values, 0, 255).astype(np.float64)[idx] /
                      255.0 * (WHITE - BLACK))

    # VIS header
    tone(1900, 300); tone(1200, 10); tone(1900, 300); tone(1200, 30)
    bits = [(mode.vis >> i) & 1 for i in range(7)]
    bits.append(sum(bits) % 2)
    for b in bits:
        tone(1100 if b else 1300, 30)
    tone(1200, 30)
    if mode.start_sync:
        tone(SYNC, mode.start_sync)

    def planes(line):
        if mode.colour in ("GBR", "RGB"):
            px = arr[line]
            return {"R": px[:, 0], "G": px[:, 1], "B": px[:, 2]}
        if mode.two_rows:
            a, b = arr[line * 2], arr[line * 2 + 1]
            return {"Y0": _lum(a, np), "Y1": _lum(b, np),
                    "RY": (_cr(a, np) + _cr(b, np)) / 2,
                    "BY": (_cb(a, np) + _cb(b, np)) / 2}
        px = arr[line]
        if mode.colour == "R36":
            return {"Y": _lum(px, np), "C": _cr(px, np) if line % 2 == 0 else _cb(px, np)}
        return {"Y": _lum(px, np), "RY": _cr(px, np), "BY": _cb(px, np)}

    for line in range(mode.lines):
        p = planes(line)
        for seg in mode.layout:
            if seg[0] == "sync":
                tone(SYNC, seg[1])
            elif seg[0] == "gap":
                tone(seg[2], seg[1])
            else:
                sweep(p[seg[2]], seg[1])

    freq = np.concatenate(pieces)
    # float64 throughout: a float32 phase accumulator loses its last digits
    # after a few million samples and quietly warps the picture.
    phase = np.cumsum(2.0 * np.pi * freq.astype(np.float64) / rate)
    audio = (np.sin(phase) * 0.7 * 32767.0).astype("<i2")
    out_path = out_path or os.path.join(
        out_dir or os.path.dirname(os.path.abspath(image_path)),
        os.path.splitext(os.path.basename(image_path))[0] + f" [{mode.name}].wav")
    with wave.open(out_path, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate)
        w.writeframes(audio.tobytes())
    return out_path, len(audio) / rate, mode


def _lum(px, np):
    return 16.0 + (0.003906 * ((65.738 * px[:, 0]) + (129.057 * px[:, 1]) + (25.064 * px[:, 2])))


def _cr(px, np):
    return 128.0 + (0.003906 * ((112.439 * px[:, 0]) + (-94.154 * px[:, 1]) + (-18.285 * px[:, 2])))


def _cb(px, np):
    return 128.0 + (0.003906 * ((-37.945 * px[:, 0]) + (-74.494 * px[:, 1]) + (112.439 * px[:, 2])))


tool(id="sstv-encode", name="Slow-scan (SSTV) encoder", category=CAT,
     summary="Turn a picture into a transmittable WAV",
     explain=("The other direction: takes an image, resizes it to the mode's frame, and writes "
              "a WAV containing the VIS header, the sync pulses and the swept tones. Play it "
              "into a transmitter, or straight back into the decoder to see the round trip.\n\n"
              "Martin M1 is the usual choice on 2 m; Robot 36 is what the ISS uses because it "
              "is quick."),
     tags=["sstv", "encode", "transmit", "wav", "ham", "radio"],
     input_kind="file", input_label="Image",
     input_types=[("Images", "*.png *.jpg *.jpeg *.gif *.bmp *.webp *.tif *.tiff"), ("All files", "*.*")],
     params=[Param("mode", "Mode", "choice", "Martin M1", choices=list(MODES)),
             Param("rate", "Sample rate", "choice", "44100", choices=["11025", "22050", "44100", "48000"]),
             Param("outdir", "Save WAV into", "folder", "")],
     action=lambda path, mode="Martin M1", rate="44100", outdir="":
         _sstv_encode_tool(path, mode, int(rate), outdir),
     action_label="Make WAV")


def _sstv_encode_tool(path, mode, rate, outdir=""):
    out, secs, m = encode_sstv(path, mode, rate, None, outdir)
    return Result(file_path=out,
                  rows=[("Mode", m.name), ("VIS code", m.vis),
                        ("Frame", f"{m.width} x {m.lines * (2 if m.two_rows else 1)}"),
                        ("Length", f"{secs:.1f} seconds"), ("Saved to", out)],
                  headers=["", ""],
                  note=f"{secs:.1f} seconds of audio written to {out}.")


# --------------------------------------------------------------------------
# DTMF
# --------------------------------------------------------------------------

DTMF_LOW = [697, 770, 852, 941]
DTMF_HIGH = [1209, 1336, 1477, 1633]
DTMF_KEYS = [["1", "2", "3", "A"], ["4", "5", "6", "B"],
             ["7", "8", "9", "C"], ["*", "0", "#", "D"]]


def goertzel(block, rate, freq):
    """Power in one frequency bin. Goertzel's recursion computes exactly this
    DFT bin; done as a dot product numpy does it far faster."""
    np = _np()
    n = len(block)
    k = int(0.5 + n * freq / rate)
    osc = np.exp(-2j * np.pi * k * np.arange(n) / n)
    return float(abs(np.dot(osc, np.asarray(block, dtype=np.float64))) ** 2)


tool(id="dtmf", name="DTMF (touch-tone) decoder", category=CAT,
     summary="Read the digits dialled in a recording",
     explain=("Every key on a telephone keypad plays two tones at once — one from a low group "
              "and one from a high group. Which pair it is identifies the key, which is why "
              "the system survives noise and why you can still hear the digits in an old "
              "recording.\n\nThis reads them back out. Useful on voicemail recordings, old "
              "answerphone tapes, capture-the-flag audio and radio repeater control tones. "
              "Takes any audio or video file."),
     tags=["touch tone", "telephone", "dial", "tones", "goertzel", "keypad"],
     input_kind="file", input_label="Audio or video file", input_types=MEDIA_TYPES,
     params=[Param("window_ms", "Analysis window (ms)", "int", 25, minimum=10, maximum=100),
             Param("threshold", "Detection threshold", "float", 8.0, minimum=1.0, maximum=100.0,
                   help="How much louder the two tones must be than the background.")],
     action=lambda path, window_ms=25, threshold=8.0: _dtmf(path, int(window_ms), float(threshold)),
     action_label="Decode tones")


def _dtmf(path, window_ms, threshold):
    np = _np()
    samples, rate = load_audio(path)
    n = int(rate * window_ms / 1000.0)
    hop = n // 2
    seq, rows, last, run, start = [], [], None, 0, 0.0
    for i in range(0, len(samples) - n, hop):
        block = samples[i:i + n]
        if np.abs(block).max() < 0.005:
            key = None
        else:
            lo = [goertzel(block, rate, f) for f in DTMF_LOW]
            hi = [goertzel(block, rate, f) for f in DTMF_HIGH]
            li, hj = int(np.argmax(lo)), int(np.argmax(hi))
            lo_rest = (sum(lo) - lo[li]) / 3 + 1e-12
            hi_rest = (sum(hi) - hi[hj]) / 3 + 1e-12
            key = DTMF_KEYS[li][hj] if (lo[li] / lo_rest > threshold and
                                        hi[hj] / hi_rest > threshold) else None
        t = i / rate
        if key != last:
            if last and run * hop / rate > 0.03:
                seq.append(last)
                rows.append((last, f"{start:.2f}s", f"{(t - start)*1000:.0f} ms"))
            last, run, start = key, 0, t
        run += 1
    if last and run * hop / rate > 0.03:
        seq.append(last)
        rows.append((last, f"{start:.2f}s", "to end"))
    if not seq:
        return Result(warn="No touch-tones found. Try lowering the threshold, or check the "
                           "recording is not too quiet or too clipped.")
    return Result(text="".join(seq), rows=rows, headers=["Key", "At", "Held for"],
                  note=f"{len(seq)} tone(s) detected.")


# --------------------------------------------------------------------------
# Morse from audio
# --------------------------------------------------------------------------

tool(id="morse-audio", name="Morse from audio", category=CAT,
     summary="Decode CW straight from a WAV recording",
     explain=("Finds the strongest tone in the recording - audio or video, any format - measures "
              "how long it is on and off, "
              "works out the dot length from the timing itself, and turns that into dots, "
              "dashes and spaces — then into letters.\n\nWorks best on a clean tone. Hand-sent "
              "Morse with uneven timing will need some patience."),
     tags=["cw", "morse", "audio", "radio", "wav", "beep"],
     input_kind="file", input_label="Audio or video file", input_types=MEDIA_TYPES,
     params=[Param("tone_hz", "Tone frequency (0 = find it)", "int", 0, minimum=0, maximum=4000),
             Param("wpm", "Speed (0 = work it out)", "int", 0, minimum=0, maximum=60)],
     action=lambda path, tone_hz=0, wpm=0: _morse_audio(path, int(tone_hz), int(wpm)),
     action_label="Decode")


def _morse_audio(path, tone_hz, wpm):
    """The file decoder runs the same engine as the live one. The streaming
    decoder is the better of the two - it re-reads its own timing as more of
    the message arrives - so there is no reason to keep a second."""
    from .live import LiveMorse
    samples, rate = load_audio(path)
    dec = LiveMorse(rate, tone_hz=int(tone_hz), wpm=int(wpm))
    step = max(2048, rate // 8)
    for i in range(0, len(samples), step):
        dec.feed(samples[i:i + step])
    text = dec.flush()
    marks = [d for m, d in dec.events if m]
    if not text:
        raise ToolError("No Morse found. Check there is a steady tone that goes on and off - "
                        "the Spectrogram tool will show you what is actually in the recording.")
    return Result(text=text,
                  rows=[("Tone", f"{dec.tone:.0f} Hz"),
                        ("Dot length", f"{dec.dot * 1000:.0f} ms" if dec.dot else "?"),
                        ("Speed", f"{1.2 / dec.dot:.0f} words per minute" if dec.dot else "?"),
                        ("Marks heard", len(marks)),
                        ("Length", f"{len(samples) / rate:.1f} seconds")],
                  headers=["", ""],
                  note="Decoded from the audio. Groups it could not match are shown as ?.")



# --------------------------------------------------------------------------
# Spectrogram
# --------------------------------------------------------------------------

tool(id="spectrogram", name="Spectrogram", category=CAT,
     summary="See the sound — and read anything hidden in it",
     explain=("Draws frequency against time, brightness for loudness. It is the first thing to "
              "do with an unknown audio file: SSTV shows as regular horizontal banding, Morse "
              "as a dotted line at one frequency, DTMF as short paired bars, and text drawn "
              "into a spectrogram (a favourite trick in puzzles and on some record sleeves) "
              "simply becomes readable.\n\nTakes any audio or video file."),
     tags=["fft", "audio", "steganography", "waterfall", "visualise"],
     input_kind="file", input_label="Audio or video file", input_types=MEDIA_TYPES,
     params=[Param("fft", "FFT size", "choice", "1024", choices=["256", "512", "1024", "2048", "4096"]),
             Param("maxhz", "Top frequency shown", "int", 5000, minimum=500, maximum=24000),
             Param("height", "Image height", "int", 512, minimum=128, maximum=2048),
             Param("colour", "Colour", "choice", "heat", choices=["heat", "grey", "green"]),
             Param("outdir", "Save picture into", "folder", "")],
     action=lambda path, fft="1024", maxhz=5000, height=512, colour="heat", outdir="":
         _spectrogram(path, int(fft), int(maxhz), int(height), colour, outdir),
     action_label="Draw")


def _spectrogram(path, nfft, maxhz, height, colour, outdir=""):
    np = _np()
    from PIL import Image
    samples, rate = load_audio(path)
    hop = nfft // 4
    frames = max(1, (len(samples) - nfft) // hop)
    frames = min(frames, 4000)
    window = np.hanning(nfft).astype(np.float32)
    cols = []
    for i in range(frames):
        seg = samples[i * hop:i * hop + nfft]
        if len(seg) < nfft:
            break
        cols.append(np.abs(np.fft.rfft(seg * window)))
    if not cols:
        raise ToolError("Recording is shorter than one FFT window.")
    mag = np.array(cols).T
    freqs = np.fft.rfftfreq(nfft, 1.0 / rate)
    keep = freqs <= maxhz
    mag = mag[keep]
    db = 20 * np.log10(mag + 1e-10)
    db = np.clip((db - db.max() + 80) / 80, 0, 1)
    db = np.flipud(db)
    img = Image.fromarray((db * 255).astype(np.uint8), "L").resize(
        (min(2000, max(400, frames)), height), Image.BILINEAR)
    a = np.asarray(img).astype(np.float32) / 255.0
    if colour == "grey":
        rgb = np.stack([a, a, a], -1)
    elif colour == "green":
        rgb = np.stack([a ** 2.5, a, a ** 2.5], -1)
    else:
        rgb = np.stack([np.clip(a * 2.2, 0, 1),
                        np.clip(a * 1.6 - 0.35, 0, 1),
                        np.clip(a * 2.4 - 1.3, 0, 1)], -1)
    out = os.path.join(outdir or os.path.dirname(os.path.abspath(path)),
                       os.path.splitext(os.path.basename(path))[0] + " [spectrogram].png")
    Image.fromarray((rgb * 255).astype(np.uint8), "RGB").save(out)
    return Result(image_path=out, file_path=out,
                  rows=[("Sample rate", f"{rate} Hz"),
                        ("Length", f"{len(samples)/rate:.1f} s"),
                        ("Frequency range", f"0 - {maxhz} Hz"),
                        ("Saved to", out)],
                  headers=["", ""],
                  note=f"{frames} frames, {nfft}-point FFT. Time runs left to right, "
                       "frequency bottom to top.")


# --------------------------------------------------------------------------
# DTMF generation - the other half of the touch-tone tool
# --------------------------------------------------------------------------

_DTMF_FREQS = {}
for _r, _row in enumerate(DTMF_KEYS):
    for _c, _key in enumerate(_row):
        _DTMF_FREQS[_key] = (DTMF_LOW[_r], DTMF_HIGH[_c])


def _dtmf_make(data, tone_ms=120, gap_ms=80, rate=8000, outdir=""):
    np = _np()
    seq = [c for c in to_text(data).upper() if c in _DTMF_FREQS]
    if not seq:
        raise ToolError("Type the digits to dial - 0-9, plus A B C D * and #.")
    rate = int(clamp(rate, 8000, 48000, 8000))
    tone_n = int(rate * clamp(tone_ms, 10, 2000, 120) / 1000.0)
    gap_n = int(rate * clamp(gap_ms, 0, 2000, 80) / 1000.0)
    t = np.arange(tone_n) / rate
    fade = np.minimum(1.0, np.minimum(np.arange(tone_n), tone_n - np.arange(tone_n)) / 80.0)
    pieces = []
    for key in seq:
        lo, hi = _DTMF_FREQS[key]
        tone = 0.4 * (np.sin(2 * np.pi * lo * t) + np.sin(2 * np.pi * hi * t)) * fade
        pieces.append(tone)
        if gap_n:
            pieces.append(np.zeros(gap_n))
    audio = np.concatenate(pieces)
    dest = os.path.join(outdir or ".", "dtmf.wav")
    with wave.open(dest, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate)
        w.writeframes((np.clip(audio, -1, 1) * 32000).astype("<i2").tobytes())
    return Result(file_path=dest,
                  rows=[("Dialled", "".join(seq)), ("Tones", len(seq)),
                        ("Length", f"{len(audio)/rate:.1f} s"), ("Saved to", dest)],
                  headers=["", ""],
                  note=f"{len(seq)} touch-tone(s) written to {dest}. Play it down a phone "
                       "line and it dials.")


tool(id="dtmf-make", name="DTMF (touch-tone) generator", category=CAT,
     summary="Turn a phone number or digit string into the touch-tones",
     explain=(
         "The reverse of the touch-tone decoder: give it a string of keypad characters and it "
         "writes the actual dual-tone audio, one pair of tones per key, exactly as a phone "
         "produces them.\n\n"
         "Handy for testing the decoder, for feeding an old phone system or repeater that "
         "listens for control tones, or just to hear what a number sounds like. Accepts 0-9, "
         "the letters A-D (the fourth column, used on some radio and military keypads) and "
         "* and #."),
     example="Dial: 0800 1234 567#",
     tags=["dtmf", "touch tone", "dial", "generate", "phone", "tones"],
     params=[Param("tone_ms", "Tone length (ms)", "int", 120, minimum=10, maximum=2000),
             Param("gap_ms", "Gap between tones (ms)", "int", 80, minimum=0, maximum=2000),
             Param("rate", "Sample rate", "int", 8000, minimum=8000, maximum=48000),
             Param("outdir", "Save into", "folder", "")],
     action=_dtmf_make, action_label="Make tones", input_kind="text")
