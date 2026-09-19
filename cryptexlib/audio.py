"""Getting sound into Cryptex: from any media file, or from a live input.

Two jobs.

*Files* - anything ffmpeg can open (mp4, mkv, mp3, m4a, ogg, flac, wav in
formats Python's own `wave` module refuses) is converted to plain 16-bit mono
PCM in a temporary file. The ffmpeg binary comes from the `imageio-ffmpeg`
package, which ships a static build, so nothing has to be installed separately.

*Live* - a callback stream from a sound card via `sounddevice`, feeding a
streaming FM discriminator. The discriminator is the piece that makes live
decoding possible at all: the offline decoder takes the whole recording and
does one big FFT, which you cannot do on sound that has not arrived yet. This
one carries its state from block to block, so frequency comes out continuously
and a decoder can consume it as it goes.
"""
from __future__ import annotations

import math
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import wave

from .core import ToolError

MEDIA_EXT = {".wav", ".mp3", ".m4a", ".aac", ".flac", ".ogg", ".oga", ".opus", ".wma",
             ".aiff", ".aif", ".caf", ".amr", ".mp4", ".m4v", ".mov", ".mkv", ".avi",
             ".webm", ".wmv", ".flv", ".ts", ".mpg", ".mpeg", ".3gp"}


# --------------------------------------------------------------------------
# ffmpeg
# --------------------------------------------------------------------------

_FFMPEG = None


def ffmpeg_exe() -> str | None:
    """Path to a usable ffmpeg, or None. Prefers the bundled static build."""
    global _FFMPEG
    if _FFMPEG is not None:
        return _FFMPEG or None
    candidates = []
    try:
        import imageio_ffmpeg
        candidates.append(imageio_ffmpeg.get_ffmpeg_exe())
    except Exception:
        pass
    for name in ("ffmpeg", "ffmpeg.exe"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for extra in ("/opt/homebrew/bin/ffmpeg", "/usr/local/bin/ffmpeg", "/usr/bin/ffmpeg"):
        if os.path.isfile(extra):
            candidates.append(extra)
    for c in candidates:
        if c and os.path.isfile(c):
            if os.name != "nt" and not os.access(c, os.X_OK):
                # PyInstaller does not always keep the executable bit on a
                # binary it carried inside a package
                try:
                    os.chmod(c, 0o755)
                except OSError:
                    continue
            _FFMPEG = c
            return c
    _FFMPEG = ""
    return None


def _no_window():
    if os.name == "nt":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return dict(startupinfo=si, creationflags=0x08000000)
    return {}


def media_info(path: str) -> str:
    """A one-line description of what ffmpeg thinks the file is."""
    exe = ffmpeg_exe()
    if not exe:
        return ""
    try:
        out = subprocess.run([exe, "-hide_banner", "-i", path],
                             capture_output=True, text=True, errors="replace",
                             stdin=subprocess.DEVNULL, timeout=30,
                             **_no_window()).stderr
    except Exception:
        return ""
    bits = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Duration:"):
            bits.append(line.split(",")[0].replace("Duration:", "").strip())
        elif "Audio:" in line:
            bits.append(line.split("Audio:")[1].split("(")[0].strip())
    return " - ".join(bits)


class Media:
    """A media file presented as plain PCM WAV, cleaned up on exit.

        with Media(path) as wav_path:
            ...
    """

    def __init__(self, path, rate=None):
        self.path = path
        self.rate = rate
        self.tmp = None
        self.wav = None
        self.converted = False

    def __enter__(self):
        self.wav, self.converted = to_pcm_wav(self.path, self.rate)
        if self.converted:
            self.tmp = self.wav
        return self.wav

    def __exit__(self, *exc):
        if self.tmp and os.path.isfile(self.tmp):
            try:
                os.unlink(self.tmp)
                os.rmdir(os.path.dirname(self.tmp))
            except OSError:
                pass
        return False


def _plain_pcm(path) -> bool:
    """True if Python's own wave module can read it as-is."""
    try:
        with wave.open(path, "rb") as w:
            return w.getsampwidth() in (1, 2, 3, 4) and w.getnframes() > 0
    except Exception:
        return False


def to_pcm_wav(path: str, rate: int | None = None) -> tuple[str, bool]:
    """Return (path to a readable PCM wav, whether it is a temporary file)."""
    if not path:
        raise ToolError("Pick a file first.")
    if not os.path.isfile(path):
        raise ToolError(f"Not a file: {path}")
    if _plain_pcm(path) and not rate:
        return path, False
    exe = ffmpeg_exe()
    if not exe:
        raise ToolError(
            "That file needs converting and no ffmpeg could be found.\n\n"
            "Install it with:  pip install imageio-ffmpeg\n"
            "(the build scripts do this for you), or install ffmpeg itself - "
            "'brew install ffmpeg' on a Mac, or from ffmpeg.org on Windows.")
    out_dir = tempfile.mkdtemp(prefix="cryptex-audio-")
    out = os.path.join(out_dir, os.path.splitext(os.path.basename(path))[0] + ".wav")
    cmd = [exe, "-hide_banner", "-loglevel", "error", "-y", "-i", path,
           "-vn", "-ac", "1"]
    if rate:
        cmd += ["-ar", str(int(rate))]
    cmd += ["-c:a", "pcm_s16le", out]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                             stdin=subprocess.DEVNULL, timeout=900, **_no_window())
    except subprocess.TimeoutExpired as exc:
        raise ToolError("ffmpeg took too long converting that file.") from exc
    if res.returncode != 0 or not os.path.isfile(out):
        raise ToolError("ffmpeg could not read that file:\n"
                        + (res.stderr or "").strip()[-500:])
    if os.path.getsize(out) < 1000:
        raise ToolError("That file has no audio track that ffmpeg could extract.")
    return out, True


# --------------------------------------------------------------------------
# Streaming FM discriminator
# --------------------------------------------------------------------------

def _lowpass_taps(rate, cutoff, ntaps=95):
    import numpy as np
    n = np.arange(ntaps) - (ntaps - 1) / 2.0
    fc = cutoff / rate
    h = 2 * fc * np.sinc(2 * fc * n)
    h *= np.blackman(ntaps)
    return (h / h.sum()).astype(np.float64)


class Discriminator:
    """Turns a stream of audio samples into a stream of frequencies.

    Mixes the audio down against a complex oscillator at `centre`, low-passes
    what is left, and takes the phase change from one sample to the next. That
    change *is* the deviation from the centre frequency. All the state needed
    to carry on across block boundaries - oscillator phase, filter history,
    last sample - is kept on the object.
    """

    def __init__(self, rate, centre=1900.0, bandwidth=1100.0, ntaps=95):
        import numpy as np
        self.np = np
        self.rate = float(rate)
        self.centre = float(centre)
        self.taps = _lowpass_taps(rate, bandwidth, ntaps)
        self.ntaps = ntaps
        self.hist = np.zeros(ntaps - 1, dtype=np.complex128)
        self.phase = 0.0
        self.prev = None
        self.warm = False

    def process(self, samples):
        """Feed audio in, get the same number of frequency values out."""
        np = self.np
        x = np.asarray(samples, dtype=np.float64).ravel()
        if x.size == 0:
            return np.empty(0, dtype=np.float32)
        step = -2.0 * math.pi * self.centre / self.rate
        ang = self.phase + step * np.arange(1, x.size + 1)
        self.phase = float(ang[-1] % (2 * math.pi))
        z = x * np.exp(1j * ang)
        buf = np.concatenate([self.hist, z])
        self.hist = buf[-(self.ntaps - 1):]
        y = np.convolve(buf, self.taps, mode="valid")      # len == x.size
        if self.prev is None:
            self.prev = y[0]
            self.warm = True
        pair = np.concatenate([[self.prev], y])
        self.prev = y[-1]
        d = np.angle(pair[1:] * np.conj(pair[:-1]))
        freq = self.centre + d * self.rate / (2.0 * math.pi)
        return np.clip(freq, 0.0, 4000.0).astype(np.float32)


def amplitude(samples):
    import numpy as np
    a = np.asarray(samples, dtype=np.float64)
    if a.size == 0:
        return 0.0
    return float(np.sqrt(np.mean(a * a)))


def level_bar(rms, width=28):
    """A text level meter - db-ish, clamped, so you can see it is hearing you."""
    if rms <= 0:
        db = -80.0
    else:
        db = 20 * math.log10(rms)
    frac = max(0.0, min(1.0, (db + 60.0) / 60.0))
    filled = int(round(frac * width))
    warn = " CLIPPING" if rms > 0.98 else (" (very quiet)" if db < -45 else "")
    return "[" + "#" * filled + "-" * (width - filled) + f"] {db:5.1f} dB{warn}"


# --------------------------------------------------------------------------
# Live capture
# --------------------------------------------------------------------------

def sounddevice():
    try:
        import sounddevice as sd
    except OSError as exc:            # the wheel is there but PortAudio is not
        raise ToolError(f"The audio library loaded but no sound system was found ({exc}).") from exc
    except ImportError as exc:
        raise ToolError("Live listening needs the sounddevice package.\n\n"
                        "Install it with:  pip install sounddevice\n"
                        "(the build scripts do this for you).") from exc
    return sd


def soundcard_lib():
    """The 'soundcard' library, which does WASAPI loopback where PortAudio can
    not. Returns None if it is not installed rather than raising, so the rest of
    the audio path keeps working without it."""
    try:
        import soundcard
        return soundcard
    except Exception:
        return None


def list_inputs():
    """[(label, index, channels, default_rate, loopback)] for every usable input.

    On Windows the output devices are listed too, as loopback: WASAPI can hand
    back whatever the machine is playing, so you can decode a video in a
    browser without any cabling. On macOS that needs a virtual device such as
    BlackHole, which then simply appears as an ordinary input.
    """
    sd = sounddevice()
    out = []
    try:
        devices = sd.query_devices()
        apis = sd.query_hostapis()
    except Exception as exc:
        raise ToolError(f"Could not list audio devices ({exc}).") from exc
    default_in = None
    try:
        default_in = sd.default.device[0]
    except Exception:
        pass
    for i, d in enumerate(devices):
        api = apis[d["hostapi"]]["name"] if d["hostapi"] < len(apis) else ""
        if d["max_input_channels"] > 0:
            tag = "  (default)" if i == default_in else ""
            out.append((f"{d['name']} [{api}]{tag}", i, d["max_input_channels"],
                        int(d["default_samplerate"]), False))
    # Loopback ("what this device is playing") on Windows goes through the
    # soundcard library, because PortAudio/sounddevice cannot do WASAPI loopback
    # at all. Each output speaker becomes a loopback entry, keyed by its name.
    if os.name == "nt":
        sc = soundcard_lib()
        if sc is not None:
            try:
                for spk in sc.all_speakers():
                    out.append((f"{spk.name} [loopback - what this device is playing]",
                                spk.name, 2, 48000, True))
            except Exception:
                pass
    if not out:
        raise ToolError("No audio input devices were found.")
    return out


class LiveSource:
    """Blocks of mono float32 audio from a sound card, via a queue."""

    def __init__(self, device=None, rate=44100, block=4096, loopback=False, channels=1):
        import queue as _q
        self.sd = sounddevice()
        self.device = device
        self.rate = int(rate)
        self.block = int(block)
        self.loopback = loopback
        self.channels = max(1, int(channels))
        self.q: _q.Queue = _q.Queue(maxsize=200)
        self.stream = None
        self.dropped = 0

    def _callback(self, indata, frames, time_info, status):  # noqa: ARG002
        import numpy as np
        try:
            data = np.asarray(indata, dtype=np.float32)
            mono = data.mean(axis=1) if data.ndim > 1 and data.shape[1] > 1 else data.ravel()
            self.q.put_nowait(mono.copy())
        except Exception:
            self.dropped += 1

    def start(self):
        sd = self.sd
        extra = None
        if self.loopback:
            try:
                extra = sd.WasapiSettings(loopback=True)
            except Exception:
                extra = None
        try:
            dev = sd.query_devices(self.device)
        except Exception:
            dev = {}
        # A WASAPI loopback stream must be opened with the *output* device's own
        # channel count and sample rate - its shared-mode mix format - not with
        # the mono the decoder wants. Getting that number wrong is what raises
        # PaErrorCode -9998 (invalid channels). Bluetooth headsets are the usual
        # culprit: they flip between a 2-channel stereo profile and a 1-channel
        # hands-free one, so the safe move is to try the device's reported count
        # first and fall back through the sensible alternatives. Whatever comes
        # in, the callback averages it down to mono.
        native_key = "max_output_channels" if self.loopback else "max_input_channels"
        native_ch = int(dev.get(native_key, 0) or 0)
        native_rate = int(dev.get("default_samplerate", self.rate) or self.rate)
        ch_opts, seen = [], set()
        for c in ([native_ch] if native_ch else []) + [self.channels, 2, 1]:
            if c and c > 0 and c not in seen:
                seen.add(c)
                ch_opts.append(c)
        rate_opts, seen_r = [], set()
        for r in [self.rate, native_rate]:
            if r and r not in seen_r:
                seen_r.add(r)
                rate_opts.append(r)
        last = None
        for r in rate_opts:
            for c in ch_opts:
                try:
                    self.stream = sd.InputStream(
                        device=self.device, channels=c, samplerate=r,
                        blocksize=self.block, dtype="float32",
                        callback=self._callback, extra_settings=extra)
                    self.stream.start()
                    self.channels, self.rate = c, r
                    return self
                except Exception as exc:
                    last = exc
                    self.stream = None
        raise ToolError(self._explain_open_failure(last))

    def _explain_open_failure(self, err):
        code = ""
        try:
            code = str(err)
        except Exception:
            code = "the sound device refused to open"
        if self.loopback:
            return ("Could not open that loopback device (" + code + ").\n\n"
                    "Loopback records whatever a device is playing, and Windows is fussy "
                    "about it - Bluetooth headphones especially, because they switch "
                    "between stereo and a mono headset mode. Things to try:\n"
                    "  - Pick a different '[loopback]' device - your actual speakers or the "
                    "PC's own output usually work where Bluetooth headphones do not.\n"
                    "  - Make sure something is actually playing through that device.\n"
                    "  - Or select a real input (a microphone, line-in or 'Stereo Mix') "
                    "instead of a loopback.")
        return ("Could not open that input (" + code + "). Try a different device or "
                "sample rate, and check nothing else has exclusive use of it.")


    def blocks(self, stop_event: threading.Event):
        import queue as _q
        while not stop_event.is_set():
            try:
                yield self.q.get(timeout=0.25)
            except _q.Empty:
                continue

    def stop(self):
        if self.stream is not None:
            try:
                self.stream.stop()
                self.stream.close()
            except Exception:
                pass
            self.stream = None


class LoopbackSource:
    """Windows WASAPI loopback via the soundcard library: blocks of mono
    float32 of whatever a speaker is playing, delivered through a queue.

    PortAudio cannot do loopback, so this is a separate backend. Recording runs
    on its own thread, so if nothing is playing (and the loopback simply waits)
    the interface stays responsive - the meter shows silence until audio flows.
    """

    def __init__(self, name=None, rate=48000, block=4096):
        import queue as _q
        self.name = name
        self.rate = int(rate)
        self.block = int(block)
        self.q: _q.Queue = _q.Queue(maxsize=200)
        self._stop = threading.Event()
        self._thread = None
        self._error = None
        self.channels = 2
        self.dropped = 0

    def start(self):
        sc = soundcard_lib()
        if sc is None:
            raise ToolError("Live loopback needs the 'soundcard' library. The built app "
                            "bundles it; from source install it with:  pip install soundcard")
        try:
            if self.name:
                self._mic = sc.get_microphone(self.name, include_loopback=True)
            else:
                self._mic = sc.get_microphone(sc.default_speaker().name, include_loopback=True)
        except Exception as exc:
            raise ToolError(f"Could not open that loopback device ({exc}). Pick a different "
                            "output, or a real input instead.")
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        # give the recorder a moment to open, and surface an immediate failure
        import time as _t
        _t.sleep(0.3)
        if self._error is not None:
            raise ToolError(f"The loopback recorder would not start ({self._error}). Try a "
                            "different output device, or use a real input.")
        return self

    def _run(self):
        import numpy as np
        try:
            with self._mic.recorder(samplerate=self.rate) as rec:
                while not self._stop.is_set():
                    data = rec.record(numframes=self.block)
                    if data is None or len(data) == 0:
                        continue
                    arr = np.asarray(data, dtype=np.float32)
                    mono = arr.mean(axis=1) if arr.ndim > 1 and arr.shape[1] > 1 else arr.ravel()
                    try:
                        self.q.put_nowait(mono.copy())
                    except Exception:
                        self.dropped += 1
        except Exception as exc:  # noqa: BLE001
            self._error = exc

    def blocks(self, stop_event: threading.Event):
        import queue as _q
        while not stop_event.is_set() and not self._stop.is_set():
            try:
                yield self.q.get(timeout=0.25)
            except _q.Empty:
                if self._error is not None:
                    return
                continue

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            try:
                self._thread.join(timeout=1.0)
            except Exception:
                pass
            self._thread = None


class FileSource:
    """A file played through the live path, optionally in real time.

    Not a toy: it is how you point the live decoder at a recording or a video,
    and it is how the self-test exercises the streaming decoders without a
    microphone.
    """

    def __init__(self, path, block=4096, realtime=False, rate=None):
        self.path = path
        self.block = int(block)
        self.realtime = realtime
        self.rate = rate
        self._media = None

    def start(self):
        import numpy as np
        self._media = Media(self.path, self.rate)
        wav = self._media.__enter__()
        from .signals import read_wav
        self.samples, self.rate = read_wav(wav)
        self.np = np
        return self

    def blocks(self, stop_event: threading.Event):
        import time
        n = self.block
        t0 = time.time()
        for i in range(0, len(self.samples), n):
            if stop_event.is_set():
                return
            chunk = self.samples[i:i + n]
            if self.realtime:
                due = t0 + (i + len(chunk)) / self.rate
                gap = due - time.time()
                if gap > 0:
                    time.sleep(min(gap, 0.5))
            yield chunk

    def stop(self):
        if self._media is not None:
            self._media.__exit__(None, None, None)
            self._media = None
