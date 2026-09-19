"""Live decoding - the same decoders, fed a sound stream instead of a file.

The difference from the file versions is that nothing here may look ahead.
Each decoder keeps its own state and consumes blocks as they arrive, emitting
partial results as it goes: an SSTV picture paints itself line by line, touch
tones and Morse append as they are heard.
"""
from __future__ import annotations

import math
import os
import time

from .core import Result, ToolError, default_save_dir
from .signals import (BLACK, MODES, SYNC, WHITE, _assemble, _np, find_vis,
                      sample_line, scan_offsets)


class LiveSSTV:
    """Streaming slow-scan decoder.

    States: LISTENING - scanning the last few seconds for a VIS header.
            DECODING  - a transmission is running; lines are read as the
                        audio for them arrives.
    """

    def __init__(self, rate, mode_name="auto", save_dir=None, smooth=True):
        np = _np()
        self.np = np
        self.rate = float(rate)
        self.mode_name = mode_name
        self.save_dir = save_dir
        self.smooth = smooth
        from .audio import Discriminator
        self.disc = Discriminator(rate)
        self.freq = np.zeros(0, dtype=np.float32)
        self.base = 0              # global index of freq[0]
        self.total = 0             # samples seen so far
        self.state = "listening"
        self.mode = None
        self.line = 0
        self.chans = {}
        self.syncs = []
        self.origin = 0.0          # global index of line 0's start
        self.line_len = 0.0
        self.offsets = None
        self.last_search = 0
        self.pictures = []         # paths of finished pictures
        self.started_at = None
        self.missed = 0

    # -------------------------------------------------------------- feeding

    def feed(self, samples):
        np = self.np
        f = self.disc.process(samples)
        if self.smooth and f.size > 4:
            k = max(3, int(self.rate // 8000))
            if k > 1:
                f = np.convolve(f, np.ones(k, dtype=np.float32) / k, mode="same")
        self.freq = np.concatenate([self.freq, f])
        self.total += f.size
        if self.state == "listening":
            self._listen()
        if self.state == "decoding":
            self._decode()
        self._trim()

    def _listen(self):
        np = self.np
        window = int(self.rate * 3.0)
        if self.total - self.last_search < int(self.rate * 0.5):
            return
        self.last_search = self.total
        tail = self.freq[-window:]
        if tail.size < int(self.rate * 1.2):
            return
        tail_base = self.base + (self.freq.size - tail.size)
        if self.mode_name != "auto":
            mode, end, code, parity = find_vis(tail, self.rate)
            mode = MODES[self.mode_name]
            if end <= 0:
                return
        else:
            mode, end, code, parity = find_vis(tail, self.rate)
            if mode is None:
                return
        self._begin(mode, tail_base + end)

    def _begin(self, mode, start_global):
        np = self.np
        self.mode = mode
        self.offsets = scan_offsets(mode)
        self.line = 0
        self.syncs = []
        self.missed = 0
        self.line_len = mode.line_ms * self.rate / 1000.0
        self.origin = float(start_global) + mode.start_sync * self.rate / 1000.0
        self.chans = {seg[2]: np.zeros((mode.lines, mode.width), dtype=np.float32)
                      for seg in mode.scans()}
        self.state = "decoding"
        self.started_at = time.time()

    # ------------------------------------------------------------- decoding

    def _g(self, lo, hi):
        """Slice the rolling buffer using global sample indices."""
        return self.freq[max(0, int(lo - self.base)):max(0, int(hi - self.base))]

    def _find_sync(self, expect_global):
        """Locate this line's pulse near where it is due. Returns a global index
        of the line start, or None."""
        np = self.np
        mode = self.mode
        sync_ms = next((s[1] for s in mode.layout if s[0] == "sync"), 9.0)
        win = max(4, int(self.rate * sync_ms / 1000.0))
        tol = int(self.line_len * 0.08)
        lo = int(expect_global - tol)
        hi = int(expect_global + tol + win)
        seg = self._g(lo, hi)
        if seg.size < win * 2:
            return None
        is_sync = (seg < 1350.0).astype(np.float32)
        energy = np.convolve(is_sync, np.ones(win, dtype=np.float32), mode="same")
        peak = int(np.argmax(energy))
        if energy[peak] < win * 0.55:
            return None
        return lo + peak - win / 2.0

    def _refit(self):
        np = self.np
        if len(self.syncs) < 8:
            return
        xs = np.array([s[0] for s in self.syncs], dtype=np.float64)
        ys = np.array([s[1] for s in self.syncs], dtype=np.float64)
        slope, intercept = np.polyfit(xs, ys, 1)
        resid = ys - (slope * xs + intercept)
        keep = np.abs(resid) < max(self.line_len * 0.02, 3 * resid.std() + 1)
        if keep.sum() >= 8:
            slope, intercept = np.polyfit(xs[keep], ys[keep], 1)
        if 0.9 < slope / (self.mode.line_ms * self.rate / 1000.0) < 1.1:
            self.line_len = float(slope)
            self.origin = float(intercept) - self.mode.sync_offset() * self.rate / 1000.0

    def _decode(self):
        mode = self.mode
        sync_off = mode.sync_offset() * self.rate / 1000.0
        guard = int(self.line_len * 0.15)
        while self.line < mode.lines:
            line_start = self.origin + self.line * self.line_len
            need_to = line_start + self.line_len + guard
            if self.base + self.freq.size < need_to:
                return                                     # not heard yet
            found = self._find_sync(line_start + sync_off)
            if found is not None:
                self.syncs.append((self.line, found))
                line_start = found - sync_off
                self._refit()
            else:
                self.missed += 1
            sample_line(self.freq, mode, line_start - self.base, self.rate,
                        self.chans, self.line, self.offsets)
            self.line += 1
        self._finish()

    def flush(self):
        """Finish the picture with whatever arrived. Called when the stream
        stops part-way through a transmission - the missing lines come out
        black rather than the whole picture being thrown away."""
        np = self.np
        if self.state != "decoding" or self.mode is None:
            return None
        need = int(self.origin + self.mode.lines * self.line_len + self.line_len)
        short = need - (self.base + self.freq.size)
        if short > 0:
            self.freq = np.concatenate(
                [self.freq, np.full(short + 16, BLACK, dtype=np.float32)])
        self._decode()
        return getattr(self, "finished_path", None)

    def _finish(self):
        path = None
        img = self.image()
        if img is not None and self.save_dir:
            stamp = time.strftime("%Y-%m-%d %H%M%S")
            path = os.path.join(self.save_dir, f"SSTV {stamp} [{self.mode.name}].png")
            try:
                img.save(path)
                self.pictures.append(path)
            except OSError:
                path = None
        self.state = "listening"
        self.last_search = self.total
        self.finished_mode = self.mode
        self.finished_path = path
        self.mode = None
        return path

    # -------------------------------------------------------------- output

    def image(self):
        if not self.chans:
            return None
        from PIL import Image
        return Image.fromarray(_assemble(self.mode or self.finished_mode,
                                         self.chans, self.np), "RGB")

    def _trim(self):
        """Keep only what is still needed, so an hour of listening does not
        turn into a gigabyte of frequencies."""
        if self.state == "listening":
            keep = int(self.rate * 4)
        else:
            line_start = self.origin + self.line * self.line_len
            keep_from = int(line_start - self.line_len)
            drop = keep_from - self.base
            if drop > self.rate:
                self.freq = self.freq[int(drop):]
                self.base += int(drop)
            return
        if self.freq.size > keep:
            drop = self.freq.size - keep
            self.freq = self.freq[drop:]
            self.base += drop

    def status(self):
        if self.state == "listening":
            return "Listening for a transmission..."
        pct = 100.0 * self.line / max(1, self.mode.lines)
        eta = (self.mode.lines - self.line) * self.mode.line_ms / 1000.0
        return (f"Receiving {self.mode.name}: line {self.line} of {self.mode.lines} "
                f"({pct:.0f}%), about {eta:.0f}s to go"
                + (f", {self.missed} sync pulse(s) missed" if self.missed else ""))


# --------------------------------------------------------------------------

DTMF_LOW = [697, 770, 852, 941]
DTMF_HIGH = [1209, 1336, 1477, 1633]
DTMF_KEYS = [["1", "2", "3", "A"], ["4", "5", "6", "B"],
             ["7", "8", "9", "C"], ["*", "0", "#", "D"]]


class LiveDTMF:
    """Streaming touch-tone decoder: Goertzel over 25 ms windows."""

    def __init__(self, rate, threshold=8.0, window_ms=25):
        np = _np()
        self.np = np
        self.rate = int(rate)
        self.threshold = float(threshold)
        self.n = max(64, int(rate * window_ms / 1000.0))
        self.buf = np.zeros(0, dtype=np.float32)
        self.digits = ""
        self.current = None
        self.run = 0
        # Goertzel computes one DFT bin; as a matrix of complex exponentials
        # numpy does all eight at once instead of 25,000 Python iterations
        # a second, which is the difference between keeping up and not.
        n = np.arange(self.n)
        self.bank = np.array([np.exp(-2j * np.pi * int(0.5 + self.n * f / rate) * n / self.n)
                              for f in DTMF_LOW + DTMF_HIGH])

    def _powers(self, block):
        np = self.np
        v = np.abs(self.bank @ block.astype(np.float64)) ** 2
        return list(v[:4]), list(v[4:])

    def feed(self, samples):
        np = self.np
        self.buf = np.concatenate([self.buf, np.asarray(samples, dtype=np.float32)])
        hop = self.n // 2
        while self.buf.size >= self.n:
            block = self.buf[:self.n]
            self.buf = self.buf[hop:]
            key = None
            if np.abs(block).max() >= 0.005:
                lo, hi = self._powers(block)
                li, hj = int(np.argmax(lo)), int(np.argmax(hi))
                lr = (sum(lo) - lo[li]) / 3 + 1e-12
                hr = (sum(hi) - hi[hj]) / 3 + 1e-12
                if lo[li] / lr > self.threshold and hi[hj] / hr > self.threshold:
                    key = DTMF_KEYS[li][hj]
            if key != self.current:
                if self.current and self.run * hop / self.rate > 0.03:
                    self.digits += self.current
                self.current, self.run = key, 0
            self.run += 1

    def flush(self):
        hop = self.n // 2
        if self.current and self.run * hop / self.rate > 0.03:
            self.digits += self.current
            self.current = None
        return self.digits

    def text(self):
        return self.digits

    def status(self):
        return f"{len(self.digits)} tone(s) heard" if self.digits else "Listening for touch-tones..."


class LiveMorse:
    """Streaming Morse decoder.

    Finds the tone, follows its envelope, and works the dot length out from
    the keying itself, so it adapts to whatever speed is being sent.
    """

    def __init__(self, rate, tone_hz=0, wpm=0):
        np = _np()
        self.np = np
        self.rate = int(rate)
        self.tone = float(tone_hz) if tone_hz else 0.0
        self.dot = (1.2 / wpm) if wpm else 0.0
        self.fixed_speed = bool(wpm)
        self.n = 0
        self.env_state = 0.0
        self.on = False
        self.run = 0
        self.events = []           # (is_mark, seconds) as heard
        self.frozen_upto = 0        # events before this are already rendered
        self.frozen_text = ""
        self.tune_buf = np.zeros(0, dtype=np.float32)
        self.pending = []          # audio held back until the tone is known
        self.peak = 0.0
        from .audio import _lowpass_taps
        self.ntaps = 127
        self.taps = _lowpass_taps(rate, 120.0, self.ntaps)   # envelope smoothing
        self.hist = np.zeros(self.ntaps - 1, dtype=np.complex128)
        self.warmup = np.zeros(0, dtype=np.float32)
        self.warm_needed = int(rate * 0.25)

    def _tune(self, block):
        np = self.np
        self.tune_buf = np.concatenate([self.tune_buf, block])[-self.rate:]
        if self.tone or self.tune_buf.size < self.rate // 3:
            return
        spec = np.abs(np.fft.rfft(self.tune_buf))
        freqs = np.fft.rfftfreq(self.tune_buf.size, 1.0 / self.rate)
        band = (freqs > 150) & (freqs < 3000)
        if band.any() and spec[band].max() > 1e-3:
            self.tone = float(freqs[band][int(np.argmax(spec[band]))])

    def feed(self, samples):
        np = self.np
        block = np.asarray(samples, dtype=np.float32)
        if not self.tone:
            # Hold the audio back rather than dropping it: the tone is usually
            # only identifiable after a fraction of a second, and those first
            # few dots are part of the message.
            self.pending.append(block)
            self._tune(block)
            if not self.tone:
                return
            block = np.concatenate(self.pending)
            self.pending = []
        t = (self.n + np.arange(block.size)) / self.rate
        self.n += block.size
        osc = np.exp(-2j * np.pi * self.tone * t)
        z = block * osc
        buf = np.concatenate([self.hist, z])
        self.hist = buf[-(self.ntaps - 1):]
        env = np.abs(np.convolve(buf, self.taps, mode="valid")).astype(np.float32)
        if self.warm_needed:
            # Hold the first quarter second back so the threshold is set from a
            # real peak; otherwise the very first dot is half-swallowed while
            # the envelope filter is still filling up.
            self.warmup = np.concatenate([self.warmup, env])
            if self.warmup.size < self.warm_needed:
                return
            env, self.warmup, self.warm_needed = self.warmup, None, 0
        self.peak = max(self.peak * 0.9995, float(env.max()) if env.size else 0.0)
        if self.peak <= 1e-6:
            return
        self._runs(env > self.peak * 0.35)

    def _runs(self, on):
        """Turn the on/off envelope into marks and gaps without looping over
        every sample: transitions only."""
        np = self.np
        if on.size == 0:
            return
        edges = np.flatnonzero(np.diff(on.astype(np.int8))) + 1
        pos = 0
        for e in list(edges) + [on.size]:
            run = int(e - pos)
            state = bool(on[pos])
            if state == self.on:
                self.run += run
            else:
                self._event(self.on, self.run / self.rate)
                self.on = state
                self.run = run
            pos = e

    def _event(self, was_mark, dur):
        """Record one keying event. Very short blips are noise, not dots."""
        if dur <= 0.008:
            return
        self.events.append((bool(was_mark), float(dur)))
        if was_mark:
            self._estimate_dot()
        if len(self.events) - self.frozen_upto > 600:
            self.frozen_text += self._render(self.events[self.frozen_upto:self.frozen_upto + 300])
            self.frozen_upto += 300

    def _estimate_dot(self):
        """Work the dot length out of the keying itself.

        Marks fall into two clusters, dots and dashes, about 1:3 apart. Split
        them at the geometric mean of the shortest and longest recent mark and
        take the lower cluster - which is far steadier than a percentile when
        a message happens to be mostly dashes, as call signs are.
        """
        if self.fixed_speed:
            return
        recent = [d for m, d in self.events[-60:] if m]
        if not recent:
            return
        lo, hi = min(recent), max(recent)
        if hi / lo >= 1.8:
            split = math.sqrt(lo * hi)
            dots = [d for d in recent if d < split]
            self.dot = sum(dots) / len(dots) if dots else lo
        else:
            self.dot = sum(recent) / len(recent)

    def _render(self, events):
        """Classify a run of events into text using the current dot length.

        Re-run over the live window every time the estimate improves, so early
        characters correct themselves as more of the message arrives.
        """
        from .encodings import MORSE_REV
        if not self.dot:
            return ""
        out, symbol = [], ""
        for is_mark, dur in events:
            u = dur / self.dot
            if is_mark:
                symbol += "." if u < 2.0 else "-"
            else:
                if u >= 2.0 and symbol:
                    out.append(MORSE_REV.get(symbol, "?"))
                    symbol = ""
                if u >= 5.0 and out and out[-1] != " ":
                    out.append(" ")
        if symbol:
            out.append(MORSE_REV.get(symbol, "?"))
        return "".join(out)

    def flush(self):
        """Close off whatever was still being sent when the stream stopped."""
        if self.on and self.run > 0:
            self._event(True, self.run / self.rate)
            self.on = False
            self.run = 0
        return self.text()

    def text(self):
        return (self.frozen_text + self._render(self.events[self.frozen_upto:])).strip()

    def status(self):
        if not self.tone:
            return "Listening for a tone..."
        wpm = (1.2 / self.dot) if self.dot else 0
        return (f"Tone {self.tone:.0f} Hz"
                + (f", about {wpm:.0f} words per minute" if wpm else "")
                + f", {len(self.text())} character(s) so far")


# --------------------------------------------------------------------------
# The tool
# --------------------------------------------------------------------------

from .core import Param, tool  # noqa: E402

CAT = "Signals"

LISTEN_EXPLAIN = (
    "Decodes sound as it arrives rather than after the event. Point it at a microphone, "
    "a line-in from a radio, or whatever the computer is playing, press Start, and watch "
    "the result build up.\n\n"
    "A slow-scan picture paints itself line by line as the transmission comes in, so you "
    "can see straight away whether you have it or whether the signal is too weak to be "
    "worth waiting four minutes for. Finished pictures are saved automatically and it goes "
    "straight back to listening for the next one.\n\n"
    "Getting the sound in:\n"
    "  - Radio to computer: a cable from the radio's headphone or data socket into the "
    "line-in or a USB sound card. A phone speaker next to a laptop microphone works "
    "surprisingly well for a strong signal.\n"
    "  - What the computer is playing (a video, a stream, a recording in another app): on "
    "Windows pick one of the '[loopback]' devices at the bottom of the list. On macOS "
    "install BlackHole or Loopback and pick it here.\n"
    "  - A file or a video you already have: choose 'A file, played through' and pick it. "
    "Leave 'real time' off to run through it as fast as the machine can manage.")


def _listen_stream(stop_event, source="Microphone or line in", device="", decode="Slow-scan (SSTV)",
                   mode="auto", save_to="", path="", realtime=True, sample_rate="44100"):
    """Generator behind the live tool: yields a Result whenever there is
    something new to show, and returns when the user presses Stop."""
    import time as _t
    from .audio import FileSource, LiveSource, amplitude, level_bar, list_inputs
    np = _np()

    use_file = source.lower().startswith("a file")
    if use_file:
        if not path:
            raise ToolError("Pick the audio or video file to play through.")
        src = FileSource(path, block=8192, realtime=bool(realtime)).start()
        rate = src.rate
        where = os.path.basename(path)
        quiet_hint = ("This file is almost silent - check it actually contains the tones, "
                      "and that it is the right file.")
    else:
        chosen = None
        inputs = list_inputs()
        if device:
            for label, idx, ch, drate, loop in inputs:
                if device.strip() == label:
                    chosen = (label, idx, ch, drate, loop)
                    break
        if chosen is None:
            chosen = inputs[0]
        label, idx, ch, drate, loop = chosen
        if loop:
            from .audio import LoopbackSource
            rate = int(sample_rate) if str(sample_rate).strip().isdigit() else 48000
            src = LoopbackSource(name=idx, rate=rate, block=4096).start()
            quiet_hint = ("This loopback is returning silence. Windows cannot tap a Bluetooth "
                          "output - it reads as silent - so route playback through a wired or "
                          "onboard output (e.g. Realtek Digital Output, or the monitor) and loop "
                          "back that device instead. Or use 'A file, played through'.")
        else:
            rate = int(sample_rate) if str(sample_rate).strip().isdigit() else int(drate)
            src = LiveSource(device=idx, rate=rate, block=4096, loopback=False,
                             channels=1).start()
            quiet_hint = "Very quiet - check the input level, or that the right device is selected."
        rate = src.rate   # start() may settle on the device's own rate
        where = label

    save_dir = save_to or default_save_dir()
    kind = decode.lower()
    if kind.startswith("slow"):
        dec = LiveSSTV(rate, mode_name=mode, save_dir=save_dir)
    elif kind.startswith("dtmf") or "touch" in kind:
        dec = LiveDTMF(rate)
    else:
        dec = LiveMorse(rate)

    started = _t.time()
    last_emit = 0.0
    since_emit = 0
    rms = 0.0
    heard = 0
    try:
        for block in src.blocks(stop_event):
            if stop_event.is_set():
                break
            rms = 0.8 * rms + 0.2 * amplitude(block)
            heard += len(block)
            dec.feed(block)
            now = _t.time()
            since_emit += 1
            # twice a second when listening live; also every 64 blocks so a
            # file run through at full speed still paints as it goes
            if now - last_emit < 0.5 and since_emit < 64:
                continue
            last_emit, since_emit = now, 0
            yield _listen_result(dec, where, rate, rms, heard, started, quiet_hint=quiet_hint)
    finally:
        try:
            dec.flush()
        except Exception:
            pass
        src.stop()
    yield _listen_result(dec, where, rate, rms, heard, started, final=True, quiet_hint=quiet_hint)


def _listen_result(dec, where, rate, rms, heard, started, final=False,
                   quiet_hint="Very quiet - check the input level or the device."):
    from .audio import level_bar
    import time as _t
    secs = heard / float(rate)
    rows = [("Source", where), ("Sample rate", f"{rate} Hz"),
            ("Heard", f"{secs:,.1f} seconds"), ("Level", level_bar(rms))]
    head = "Stopped. " if final else ""
    if final and isinstance(dec, LiveSSTV) and dec.pictures:
        head = (f"Stopped. {len(dec.pictures)} picture(s) saved, "
                f"latest {os.path.basename(dec.pictures[-1])}. ")
    if isinstance(dec, LiveSSTV):
        img = dec.image()
        path = None
        if img is not None:
            from .core import app_dir
            path = os.path.join(app_dir(), "cryptex-live-preview.png")
            try:
                img.save(path)
            except OSError:
                path = None
        rows.append(("Pictures saved", len(dec.pictures)))
        if dec.pictures:
            rows.append(("Latest", dec.pictures[-1]))
        return Result(image_path=path, rows=rows, headers=["", ""],
                      note=head + dec.status() + "   " + level_bar(rms, 20),
                      warn=(quiet_hint if rms < 0.004 and secs > 3 else ""))
    text = dec.text()
    return Result(text=text, rows=rows, headers=["", ""], prefer="text",
                  note=head + dec.status(),
                  warn=(quiet_hint if rms < 0.004 and secs > 3 else ""))


def _input_choices():
    """Device names for the dropdown, resolved lazily so the app still starts
    on a machine with no sound card at all."""
    try:
        from .audio import list_inputs
        return [label for label, *_rest in list_inputs()]
    except Exception:
        return []


def _from_file(v):
    return str(v.get("source", "")).lower().startswith("a file")


def _from_device(v):
    return not _from_file(v)


def _is_sstv(v):
    return str(v.get("decode", "")).lower().startswith("slow")


tool(id="listen", name="Listen and decode (live)", category=CAT,
     summary="Decode slow-scan pictures, touch-tones or Morse as they are heard",
     explain=LISTEN_EXPLAIN,
     tags=["live", "listen", "microphone", "mic", "realtime", "real time", "sstv",
           "radio", "loopback", "stream", "monitor", "receive", "rx"],
     input_kind="none",
     params=[Param("source", "Sound from", "choice", "Microphone or line in",
                   choices=["Microphone or line in", "A file, played through"]),
             Param("device", "Input device", "choice", "", choices=_input_choices,
                   visible_when=_from_device,
                   help="Windows: the '[loopback]' entries decode whatever that device is "
                        "playing. macOS: install BlackHole to do the same."),
             Param("sample_rate", "Sample rate", "choice", "auto (device default)",
                   choices=["auto (device default)", "11025", "22050", "44100", "48000"],
                   visible_when=_from_device,
                   help="Auto uses whatever the chosen device runs at."),
             Param("path", "File", "file", "", visible_when=_from_file,
                   help="Any audio or video file."),
             Param("realtime", "Play the file at normal speed", "bool", True,
                   visible_when=_from_file,
                   help="Off runs through the file as fast as it can."),
             Param("decode", "Decode as", "choice", "Slow-scan (SSTV)",
                   choices=["Slow-scan (SSTV)", "DTMF touch-tones", "Morse (CW)"]),
             Param("mode", "SSTV mode", "choice", "auto", choices=["auto"] + list(MODES),
                   visible_when=_is_sstv,
                   help="Leave on auto - the VIS header says which mode it is."),
             Param("save_to", "Save pictures to", "folder", "", visible_when=_is_sstv,
                   help="Blank saves them in your default save folder (File menu).")],
     stream=_listen_stream,
     start_label="Start listening", stop_label="Stop")
