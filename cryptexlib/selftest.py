"""Self-test: exercise every registered tool and report what fails.

Run with:  cryptex selftest      (or: python cryptex.py selftest)

Every encode/decode pair is round-tripped, every single-direction tool is run,
and the slow-scan encoder and decoder are pointed at each other with a
generated test card. Anything that throws, or fails to come back to what went
in, is reported by name.
"""
from __future__ import annotations

import os
import tempfile
import traceback

from .core import REGISTRY, Result, as_result, to_text

# What to feed each tool. Anything not listed here uses the generic sample.
SAMPLE = "Attack at dawn, bring the maps. 12 men, 3 carts."
CASES: dict[str, dict] = {
    "base64": dict(text="Hello world!"),
    "base32": dict(text="Hello world!"),
    "base16": dict(text="Hello world!"),
    "base85": dict(text="Hello world!"),
    "base58": dict(text="Hello world!"),
    "url": dict(text="a b&c=d?e/f #g"),
    "html": dict(text="<b>Bell & Co</b> said 'hi'"),
    "quopri": dict(text="café = good"),
    "punycode": dict(text="münchen.de", loose=True),
    "uu": dict(text="Hello world!"),
    "binary": dict(text="Hi there"),
    "unicode-escape": dict(text="café naïve"),
    "morse": dict(text="SOS HELP", expect="SOS HELP"),
    "nato": dict(text="AB12", expect="AB12"),
    "bacon": dict(text="HELLO", expect="HELLO"),
    "tap": dict(text="HELLO", expect="HELLO"),
    "braille": dict(text="Hi 42", expect="Hi 42"),
    "baudot": dict(text="HELLO 123", expect="HELLO 123"),
    "leet": dict(text="hello", loose=True),   # lossy by nature: i and l both become 1
    "reverse": dict(text="Hello world"),
    "caesar": dict(text="ATTACK AT DAWN", params=dict(shift=3)),
    "atbash": dict(text="HELLO", expect="HELLO"),
    "affine": dict(text="HELLO", params=dict(a=5, b=8)),
    "vigenere": dict(text="ATTACKATDAWN", params=dict(key="LEMON")),
    "running-key": dict(text="HELLO", params=dict(key="THEQUICKBROWNFOXJUMPS")),
    "polybius": dict(text="HELLO", params=dict(key="CRYPTO"), expect="HELLO"),
    "playfair": dict(text="HIDETHEGOLD", params=dict(key="MONARCHY"), loose=True),
    "adfgvx": dict(text="ATTACKATONCE", params=dict(trans_key="PRIVACY"), expect="ATTACKATONCE"),
    "railfence": dict(text="WEAREDISCOVERED", params=dict(rails=3)),
    "columnar": dict(text="WEAREDISCOVERED", params=dict(key="ZEBRAS"), loose=True),
    "scytale": dict(text="IAMHURTVERYBADLY", params=dict(n=4)),
    "substitution": dict(text="HELLO WORLD", params=dict(keyword="ZEBRA")),
    "xor": dict(text="Attack at dawn", params=dict(key="secret", out_format="hex"),
                decode_params=dict(key="secret", in_format="hex", out_format="text")),
    "otp": dict(text="HELLO", params=dict(pad="XMCKLXMCKL"), expect="HELLO"),
    "aes-text": dict(text="Meet at nine.", params=dict(password="hunter2", work=20000),
                     decode_params=dict(password="hunter2")),
    "rsa-crypt": dict(skip="needs a key pair; covered by the key-pair test below"),
    "sign": dict(skip="covered by the key-pair test below"),
    "case": dict(text="hello world", params=dict(style="UPPER")),
    "identify": dict(text="SGVsbG8gd29ybGQh"),
    "a1z26": dict(text="ATTACK AT DAWN", expect="ATTACK AT DAWN"),
    "rot47": dict(text="Meet me at nine, 42 times!"),
    "base62": dict(text="Hello world"),
    "compress": dict(text="the same words over and over " * 6),
    "auto-solve": dict(skip="exercised separately"),
    "freq": dict(text=SAMPLE),
    "entropy": dict(text=SAMPLE),
    "hexdump": dict(text=SAMPLE),
    "kasiski": dict(text="ABCDEFABCDEFABCDEFABCDEFABCDEF"),
    "diff": dict(text="hello world", params=dict(other="hello there")),
    "caesar-brute": dict(text="Dwwdfn dw gdzq"),
    "vigenere-solve": dict(text=None),        # built below
    "xor-crack": dict(text=None),             # built below
    "unicode-normalise": dict(text="café​"),
    "hash-text": dict(text=SAMPLE),
    "hmac": dict(text=SAMPLE, params=dict(key="k1")),
    "password-hash": dict(text="hunter2", params=dict(iterations=20000)),
    "keygen": dict(params=dict(algo="Ed25519")),
    "selfsigned": dict(params=dict(common_name="test.local", days=30, algo="ECDSA P-256")),
    "inspect-key": dict(text=None),           # built below
    "dh": dict(text=None),                    # built below
    "password-gen": dict(params=dict(style="passphrase", length=5, count=2)),
    "random": dict(params=dict(nbytes=16, fmt="hex")),
    "shred": dict(skip="destructive; exercised separately"),
    "aes-file": dict(skip="exercised separately"),
    "aes-folder": dict(skip="exercised separately"),
    "hash-file": dict(skip="exercised separately"),
    "compare-files": dict(skip="exercised separately"),
    "sstv-decode": dict(skip="exercised separately"),
    "sstv-encode": dict(skip="exercised separately"),
    "dtmf": dict(skip="exercised separately"),
    "morse-audio": dict(skip="exercised separately"),
    "spectrogram": dict(skip="exercised separately"),
    "enigma": dict(text="ATTACKATDAWNTHEWEATHERISFINE", expect="ATTACKATDAWNTHEWEATHERISFINE",
                   params=dict(rotor1="I", rotor2="II", rotor3="III", rings="AAA",
                               positions="AAA", plugboard="AB CD", groups=0)),
    "enigma-crack": dict(skip="exercised separately"),
    "crib-drag": dict(text=None),             # built below
    "zero-width": dict(text="meet at nine", params=dict(cover="Lunch at one?"),
                       expect="meet at nine"),
    "shamir": dict(text="correct horse battery staple",
                   params=dict(shares=5, threshold=3),
                   expect="correct horse battery staple"),
    "jwt": dict(text='{"sub":"1234","name":"Dan"}', params=dict(secret="k" * 32),
                loose=True),
    "totp": dict(text="JBSWY3DPEHPK3PXP"),
    "totp-new": dict(params=dict(bits=160)),
    "rtty-make": dict(skip="exercised separately"),
    "psk31-make": dict(skip="exercised separately"),
    "aprs-make": dict(skip="exercised separately"),
    "rtty": dict(skip="exercised separately"),
    "psk31": dict(skip="exercised separately"),
    "aprs": dict(skip="exercised separately"),
    "lsb-hide": dict(skip="exercised separately"),
    "lsb-extract": dict(skip="exercised separately"),
    "bitplane": dict(skip="exercised separately"),
    "carve": dict(skip="exercised separately"),
    "exif": dict(skip="exercised separately"),
    "manifest": dict(skip="exercised separately"),
    "manifest-check": dict(skip="exercised separately"),
    "listen": dict(skip="exercised separately"),
    "defang": dict(text="Visit http://evil.example.com/path and mail bad@evil.com",
                   expect="Visit http://evil.example.com/path and mail bad@evil.com"),
    "timestamps": dict(text="1758196800", expect_in="2025"),
    "ip-tools": dict(text="8.8.8.8", expect_in="global"),
    "url-dissect": dict(text="https://x.example.com/a?id=1&utm_source=e&fbclid=z",
                        expect_in="tracking"),
    "email-headers": dict(text=None),
    "validate-id": dict(text="4111111111111111", expect_in="Visa"),
    "dtmf-make": dict(skip="exercised separately"),
    "audio-hide": dict(skip="exercised separately"),
    "audio-extract": dict(skip="exercised separately"),
    "stego-detect": dict(skip="exercised separately"),
    "whitespace": dict(text="the vault code is 4471",
                       params=dict(cover="Dear team,\nThe report is ready.\nRegards,\nDan"),
                       expect="the vault code is 4471"),
    "password-strength": dict(text="hunter2", expect_in="Very weak"),
    "porta": dict(text="ATTACKATDAWN", params=dict(key="FORTIFICATION"), expect="ATTACKATDAWN"),
    "gronsfeld": dict(text="ATTACKATDAWN", params=dict(key="31415")),
    "bifid": dict(text="ATTACKATDAWN", params=dict(key="CIPHER", period=5), expect="ATTACKATDAWN"),
    "trifid": dict(text="ATTACKATDAWN", params=dict(key="CRYPTO", period=5), expect="ATTACKATDAWN"),
    "four-square": dict(text="ATTACKATDAWN", params=dict(key1="EXAMPLE", key2="KEYWORD"),
                        loose=True),
    "nihilist": dict(text="ATTACKATDAWN", params=dict(key="MOSCOW", square_key="RUSSIAN"),
                     expect="ATTACKATDAWN"),
    "hill": dict(text="ATTACKATDAWN", params=dict(key="GYBNQKURP"), expect="ATTACKATDAWN"),
    "fractionated-morse": dict(text="ATTACK", params=dict(key="CIPHER"), expect="ATTACK"),
    "base45": dict(text="Hello world!"),
    "z85": dict(text="ABCDEFGH"),
    "base91": dict(text="Hello world!"),
    "xxencode": dict(text="Hello world!"),
    "cipher-id": dict(text="WKHTXLFNEURZQIRAMXPSVRYHUWKHODCBGRJDQGWKHQWKHHDJOHODQGV"),
    "hash-crack": dict(text="0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e", expect_in="password1"),
    "age": dict(skip="exercised separately"),
    "age-keygen": dict(skip="exercised separately"),
    "convert-key": dict(skip="exercised separately"),
    "pkcs12": dict(skip="exercised separately"),
    "qr": dict(skip="exercised separately"),
}


def _text(v):
    return as_result(v).text if not isinstance(v, str) else v


def run(verbose=True):
    from . import registry  # noqa: F401  (registers everything)
    from .classical import _vig
    from .core import ToolError

    results = []      # (name, "PASS"/"FAIL"/"SKIP", detail)

    def record(name, ok, detail=""):
        results.append((name, "PASS" if ok else "FAIL", detail))
        if verbose:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))

    def skip(name, why):
        results.append((name, "SKIP", why))

    # ---- build the cases that need generated material
    CASES["vigenere-solve"]["text"] = _vig(
        "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDTHENTHEATTACKBEGINSATDAWN"
        "WITHALLTHEFORCESWEHAVEAVAILABLETOUSTHISMORNINGANDWESHALLNOTFAIL",
        "LEMON", "Vigenere", True, False)
    CASES["vigenere-solve"]["expect_in"] = "THEQUICK"
    xt = REGISTRY["xor"].encode("Attack at dawn, bring the maps and the money too and all the men",
                                key="secret", out_format="hex")
    CASES["xor-crack"]["text"] = _text(xt)
    CASES["xor-crack"]["params"] = dict(maxlen=16, input_format="hex")
    CASES["xor-crack"]["expect_in"] = "Attack at dawn"

    CASES["email-headers"]["text"] = (
        "Received: from mail.evil.example (mail.evil.example [203.0.113.9]) "
        "by mx.good.com; Thu, 18 Sep 2025 12:00:00 +0000\n"
        "From: CEO <ceo@good.com>\nTo: victim@good.com\nSubject: Urgent\n"
        "Authentication-Results: mx.good.com; spf=fail dkim=fail")
    CASES["email-headers"]["expect_in"] = "hop"

    key = b"SUPERSECRETKEY" * 8
    plain = b"the meeting is at noon tomorrow by the old bridge as agreed"
    CASES["crib-drag"]["text"] = bytes(a ^ b for a, b in zip(plain, key)).hex()
    CASES["crib-drag"]["params"] = dict(crib=" the ", input_format="hex")

    kp = REGISTRY["keygen"].action(algo="Ed25519", ssh=False)
    priv = kp.text.split("-----END PRIVATE KEY-----")[0] + "-----END PRIVATE KEY-----"
    pub = "-----BEGIN PUBLIC KEY-----" + kp.text.split("-----BEGIN PUBLIC KEY-----")[1]
    CASES["inspect-key"]["text"] = pub
    x1 = REGISTRY["keygen"].action(algo="X25519 (key exchange)", ssh=False)
    x2 = REGISTRY["keygen"].action(algo="X25519 (key exchange)", ssh=False)

    def split(t):
        return (t.split("-----END PRIVATE KEY-----")[0] + "-----END PRIVATE KEY-----",
                "-----BEGIN PUBLIC KEY-----" + t.split("-----BEGIN PUBLIC KEY-----")[1])
    a_priv, a_pub = split(x1.text)
    b_priv, b_pub = split(x2.text)
    CASES["dh"]["params"] = dict(mine=a_priv, theirs=b_pub)

    if verbose:
        print(f"Cryptex self-test: {len(REGISTRY)} tools\n")

    # ---- every registered tool
    for tid, tool in REGISTRY.items():
        case = CASES.get(tid, {})
        if case.get("skip"):
            skip(tool.name, case["skip"])
            continue
        params = dict(case.get("params") or {})
        text = case.get("text", SAMPLE)
        try:
            if tool.encode and tool.decode:
                enc = _text(tool.encode(text, **params))
                dec_params = dict(case.get("decode_params") or case.get("second_pass") or params)
                dec = _text(tool.decode(enc, **dec_params))
                want = case.get("expect", text)
                if case.get("loose"):
                    ok = bool(dec)
                else:
                    ok = dec.strip() == want.strip() or dec.replace(" ", "") == want.replace(" ", "")
                record(tool.name, ok, "" if ok else f"{text!r} -> {enc[:28]!r} -> {dec[:40]!r}")
            elif tool.action:
                out = as_result(tool.action(**params) if tool.input_kind == "none"
                                else tool.action(text, **params))
                blob = (out.text or "") + " " + " ".join(
                    str(v) for r in (out.rows or []) for v in r) + " " + out.note + " " + out.warn
                need = case.get("expect_in")
                ok = bool(blob.strip()) and (need is None or need in blob)
                record(tool.name, ok, "" if ok else f"no usable output (wanted {need!r})")
            elif tool.encode:
                record(tool.name, bool(_text(tool.encode(text, **params))))
            else:
                skip(tool.name, "nothing to run")
        except Exception as exc:                                  # noqa: BLE001
            record(tool.name, False, f"{type(exc).__name__}: {exc}")
            if verbose and not isinstance(exc, ToolError):
                traceback.print_exc()

    # ---- signatures, file encryption and slow-scan, end to end
    tmp = tempfile.mkdtemp(prefix="cryptex-selftest-")
    try:
        sig = REGISTRY["sign"].encode("the message", key=priv)
        good = REGISTRY["sign"].decode("the message", key=pub, signature=_text(sig))
        bad = REGISTRY["sign"].decode("the messagE", key=pub, signature=_text(sig))
        record("Sign & verify (round trip)",
               "VALID" in as_result(good).note and "INVALID" in as_result(bad).warn)

        rk = REGISTRY["keygen"].action(algo="RSA 2048", ssh=False)
        rpriv = rk.text.split("-----END PRIVATE KEY-----")[0] + "-----END PRIVATE KEY-----"
        rpub = "-----BEGIN PUBLIC KEY-----" + rk.text.split("-----BEGIN PUBLIC KEY-----")[1]
        ct = REGISTRY["rsa-crypt"].encode("top secret", key=rpub)
        pt = REGISTRY["rsa-crypt"].decode(_text(ct), key=rpriv)
        record("Encrypt with a public key (round trip)", as_result(pt).text == "top secret")

        shared1 = REGISTRY["dh"].action(mine=a_priv, theirs=b_pub).text
        shared2 = REGISTRY["dh"].action(mine=b_priv, theirs=a_pub).text
        record("Shared secret (both sides agree)", shared1 == shared2 and len(shared1) == 64)

        src = os.path.join(tmp, "plain.bin")
        with open(src, "wb") as fh:
            fh.write(os.urandom(1500) * 800)          # ~1.2 MB, crosses a chunk
        original = open(src, "rb").read()
        enc = REGISTRY["aes-file"].encode(src, password="pw", work=20000)
        os.rename(src, src + ".orig")
        REGISTRY["aes-file"].decode(enc.file_path, password="pw")
        record("Encrypt a file (round trip)", open(src, "rb").read() == original)
        try:
            REGISTRY["aes-file"].decode(enc.file_path, password="wrong")
            record("Encrypt a file (rejects a wrong password)", False, "it did not refuse")
        except Exception:
            record("Encrypt a file (rejects a wrong password)", True)

        h1 = REGISTRY["hash-file"].action(src + ".orig", algo="sha256")
        v = REGISTRY["hash-file"].action(src + ".orig", algo="sha256", expected=h1.text)
        record("Hash a file (verify)", "MATCH" in v.note)
        record("Compare two files",
               "IDENTICAL" in REGISTRY["compare-files"].action(src, other=src + ".orig").note)

        junk = os.path.join(tmp, "junk.txt")
        open(junk, "w").write("x" * 500)
        REGISTRY["shred"].action(junk, passes=1, confirm=True)
        record("Securely delete a file", not os.path.exists(junk))

        ok, why = _sstv_check(tmp)
        record("Slow-scan encode/decode (every mode)", ok, why)

        ok, why = _media_check(tmp)
        record("Audio/video file conversion (ffmpeg)", ok, why)

        ok, why = _live_check(tmp)
        record("Live decoding (SSTV, touch-tones, Morse)", ok, why)

        ok, why = _solver_check()
        record("Auto-solve (layered puzzles)", ok, why)

        ok, why = _stego_check(tmp)
        record("Steganography (hide, find and carve)", ok, why)

        ok, why = _radio_check(tmp)
        record("RTTY, PSK31 and packet (round trip, and in noise)", ok, why)

        ok, why = _tokens_check(tmp)
        record("TOTP, JWT, Shamir and manifests", ok, why)

        ok, why = _enigma_check()
        record("Enigma (machine and solver)", ok, why)

        ok, why = _interop_check(tmp)
        record("Interop (age, key/cert formats, PKCS#12)", ok, why)

        ok, why = _qr_check(tmp)
        record("QR codes", ok, why)


        ok, why = _signals2_check(tmp)
        record("DTMF generation, audio & whitespace stego, detection", ok, why)
    except Exception as exc:                                       # noqa: BLE001
        record("End-to-end checks", False, f"{type(exc).__name__}: {exc}")
        if verbose:
            traceback.print_exc()
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(1 for _n, s, _d in results if s == "PASS")
    failed = [r for r in results if r[1] == "FAIL"]
    skipped = sum(1 for _n, s, _d in results if s == "SKIP")
    lines = [f"Cryptex self-test", "",
             f"{passed} passed, {len(failed)} failed, {skipped} skipped "
             f"(of {len(REGISTRY)} registered tools).", ""]
    if failed:
        lines.append("PROBLEMS FOUND:")
        lines += [f"  {n}: {d}" for n, _s, d in failed]
    else:
        lines.append("No problems found.")
    report = "\n".join(lines)
    try:
        from .core import app_dir
        with open(os.path.join(app_dir(), "cryptex-selftest.txt"), "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    except Exception:
        pass
    if verbose:
        print("\n" + report)
    return 0 if not failed else 1


def _solver_check():
    """Build layered puzzles, hand each to the auto-solver, and check it gets
    the message back. This is the test that matters most: it exercises the
    decoders, the brute-force sweeps, the scoring and the search at once."""
    import base64
    import gzip
    import urllib.parse
    from .solver import solve
    PT = "Meet me at the old mill at nine tonight and bring the money that you owe"
    LONG = ("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THEN THE ATTACK BEGINS AT "
            "DAWN WITH ALL THE FORCES WE HAVE AVAILABLE TO US THIS MORNING AND WE SHALL "
            "NOT FAIL IN OUR DUTY TO THE CAUSE")
    caesar = REGISTRY["caesar"].encode
    want_mill = "MEETMEATTHEOLDMILL"
    puzzles = [
        ("Base64", base64.b64encode(PT.encode()).decode(), want_mill),
        ("hex", PT.encode().hex(), want_mill),
        ("Base64 of Caesar", base64.b64encode(caesar(PT, shift=7).encode()).decode(), want_mill),
        ("Caesar then reversed", caesar(PT, shift=13)[::-1], want_mill),
        ("Base64 of gzip", base64.b64encode(gzip.compress(PT.encode())).decode(), want_mill),
        ("URL of Base64 of hex",
         urllib.parse.quote(base64.b64encode(PT.encode().hex().encode()).decode(), safe=""),
         want_mill),
        ("Morse", REGISTRY["morse"].encode("ATTACK AT DAWN BRING THE MAPS"), "ATTACKATDAWN"),
        ("A1Z26", REGISTRY["a1z26"].encode("MEET ME AT THE OLD MILL"), want_mill),
        ("single-byte XOR",
         REGISTRY["xor"].encode(PT, key="5a", key_format="hex", out_format="hex").text, want_mill),
        ("repeating-key XOR",
         base64.b64encode(bytes(b ^ ord("secret"[i % 6])
                                for i, b in enumerate(PT.encode()))).decode(), want_mill),
        ("rail fence", REGISTRY["railfence"].encode(PT.upper().replace(" ", ""), rails=4), want_mill),
        ("scytale", REGISTRY["scytale"].encode(PT.upper().replace(" ", ""), n=5), want_mill),
        ("Atbash", REGISTRY["atbash"].encode(PT.upper()), want_mill),
        ("ROT47", REGISTRY["rot47"].encode(PT), want_mill),
        ("affine", REGISTRY["affine"].encode(PT.upper(), a=5, b=8), want_mill),
        ("binary", REGISTRY["binary"].encode(PT), want_mill),
        ("Base32 of Base64",
         base64.b32encode(base64.b64encode(PT.encode())).decode(), want_mill),
        ("Base58", REGISTRY["base58"].encode(PT.encode()), want_mill),
        ("Vigenere", REGISTRY["vigenere"].encode(LONG, key="LEMON"), "QUICKBROWNFOX"),
        ("Base64 of XOR of gzip",
         base64.b64encode(bytes(b ^ 0x2a for b in gzip.compress(PT.encode()))).decode(), want_mill),
    ]
    bad = []
    for name, payload, want in puzzles:
        try:
            found, _expanded, _timeout = solve(payload, 4, 20.0)
        except Exception as exc:                                   # noqa: BLE001
            bad.append(f"{name} ({type(exc).__name__}: {exc})")
            continue
        if not found:
            bad.append(f"{name} (nothing found)")
            continue
        got = str(found[0].value).upper().replace(" ", "")
        if want not in got:
            bad.append(f"{name} (got {found[0].recipe()})")
    # and it must NOT invent an answer for something genuinely encrypted
    try:
        blob = REGISTRY["aes-text"].encode(PT, password="pw", work=20000).text
        found, _e, _t = solve(blob, 3, 8.0)
        if found and found[0].score > 0.55:
            bad.append("claimed to solve properly encrypted data")
    except Exception as exc:                                       # noqa: BLE001
        bad.append(f"encrypted check ({exc})")
    return (not bad), ("; ".join(bad) if bad else
                       f"{len(puzzles)} layered puzzles solved, encrypted data correctly refused")


def _test_card(tmp):
    import numpy as np
    from PIL import Image
    w, h = 320, 256
    a = np.zeros((h, w, 3), dtype=np.uint8)
    for i, col in enumerate([(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 0),
                             (0, 255, 255), (255, 0, 255), (255, 255, 255), (64, 64, 64)]):
        a[:, i * 40:(i + 1) * 40] = col
    card = os.path.join(tmp, "card.png")
    Image.fromarray(a).save(card)
    return card, a.astype(float), w, h


def _media_check(tmp):
    """Encode a picture to WAV, transcode it to mp3 and to an mp4 with ffmpeg,
    and check both still decode. This is the whole any-file-format path."""
    import subprocess
    import numpy as np
    from PIL import Image
    from .audio import ffmpeg_exe
    exe = ffmpeg_exe()
    if not exe:
        return False, "no ffmpeg found (pip install imageio-ffmpeg)"
    card, ref, w, h = _test_card(tmp)
    wav = REGISTRY["sstv-encode"].action(card, mode="Martin M1", rate="22050").file_path
    bad = []
    for name, args in (("mp3", ["-c:a", "libmp3lame", "-b:a", "128k"]),
                       ("m4a", ["-c:a", "aac", "-b:a", "128k"]),
                       ("flac", ["-c:a", "flac"])):
        out = os.path.join(tmp, "clip." + name)
        r = subprocess.run([exe, "-hide_banner", "-loglevel", "error", "-y", "-i", wav]
                           + args + [out], capture_output=True, text=True)
        if r.returncode != 0 or not os.path.isfile(out):
            bad.append(f"{name} (ffmpeg: {(r.stderr or '').strip()[:80]})")
            continue
        try:
            dec = REGISTRY["sstv-decode"].action(out)
            got = np.asarray(Image.open(dec.image_path).convert("RGB")
                             .resize((w, h))).astype(float)
            err = float(np.abs(got - ref).mean())
            if dec.rows[0][1] != "Martin M1" or err > 15.0:
                bad.append(f"{name} (error {err:.1f})")
            os.unlink(dec.image_path)
        except Exception as exc:                                   # noqa: BLE001
            bad.append(f"{name} ({type(exc).__name__}: {exc})")
    os.unlink(wav)
    return (not bad), ("; ".join(bad) if bad else "mp3, m4a and flac all decoded")


def _live_check(tmp):
    """Run recordings through the live path - the streaming decoders, fed in
    blocks with no ability to look ahead - and check they come out right."""
    import threading
    import wave
    import numpy as np
    from PIL import Image
    from .encodings import MORSE
    from .live import LiveDTMF, LiveMorse, LiveSSTV
    from .signals import DTMF_HIGH, DTMF_KEYS, DTMF_LOW, read_wav
    bad = []

    card, ref, w, h = _test_card(tmp)
    for mode in ("Martin M1", "Scottie S1", "Robot 36", "PD90"):
        try:
            wav = REGISTRY["sstv-encode"].action(card, mode=mode, rate="22050").file_path
            samples, rate = read_wav(wav)
            dec = LiveSSTV(rate, save_dir=tmp)
            for i in range(0, len(samples), 4096):
                dec.feed(samples[i:i + 4096])
            dec.flush()
            got_mode = getattr(dec, "finished_mode", None)
            img = dec.image()
            err = float(np.abs(np.asarray(img.convert("RGB").resize((w, h))).astype(float)
                               - ref).mean()) if img else 999.0
            if not got_mode or got_mode.name != mode or err > 15.0:
                bad.append(f"live {mode} (got {got_mode and got_mode.name}, error {err:.1f})")
            os.unlink(wav)
        except Exception as exc:                                   # noqa: BLE001
            bad.append(f"live {mode} ({type(exc).__name__}: {exc})")

    def write(path, x, r):
        with wave.open(path, "wb") as wv:
            wv.setnchannels(1); wv.setsampwidth(2); wv.setframerate(r)
            wv.writeframes((np.clip(x, -1, 1) * 32767).astype("<i2").tobytes())

    try:
        r, parts = 8000, []
        keys = {DTMF_KEYS[i][j]: (lo, hi)
                for i, lo in enumerate(DTMF_LOW) for j, hi in enumerate(DTMF_HIGH)}
        want = "0123456789*#ABCD"
        for ch in want:
            lo, hi = keys[ch]
            t = np.arange(int(r * 0.12)) / r
            parts.append(0.5 * (np.sin(2 * np.pi * lo * t) + np.sin(2 * np.pi * hi * t)))
            parts.append(np.zeros(int(r * 0.06)))
        p = os.path.join(tmp, "dtmf.wav")
        write(p, np.concatenate(parts), r)
        samples, rate = read_wav(p)
        d = LiveDTMF(rate)
        for i in range(0, len(samples), 2048):
            d.feed(samples[i:i + 2048])
        if d.flush() != want:
            bad.append(f"live DTMF (got {d.flush()!r})")
        if REGISTRY["dtmf"].action(p).text != want:
            bad.append("file DTMF disagreed with live DTMF")
        spec = REGISTRY["spectrogram"].action(p, fft="512", maxhz=2000, height=128)
        if not spec.image_path or not os.path.exists(spec.image_path):
            bad.append("the spectrogram wrote nothing")
    except Exception as exc:                                       # noqa: BLE001
        bad.append(f"live DTMF ({type(exc).__name__}: {exc})")

    try:
        msg, dot, r, out = "CQ DE M0ABC K", 1.2 / 18, 8000, []
        out.append(np.zeros(int(r * dot * 3)))
        for wi, word in enumerate(msg.split()):
            for li, ch in enumerate(word):
                for si, sym in enumerate(MORSE[ch]):
                    n = int(r * dot * (1 if sym == "." else 3))
                    t = np.arange(n) / r
                    out.append(0.6 * np.sin(2 * np.pi * 700 * t))
                    if si < len(MORSE[ch]) - 1:
                        out.append(np.zeros(int(r * dot)))
                if li < len(word) - 1:
                    out.append(np.zeros(int(r * dot * 3)))
            if wi < len(msg.split()) - 1:
                out.append(np.zeros(int(r * dot * 7)))
        out.append(np.zeros(int(r * dot * 3)))
        p = os.path.join(tmp, "cw.wav")
        write(p, np.concatenate(out), r)
        samples, rate = read_wav(p)
        m = LiveMorse(rate)
        for i in range(0, len(samples), 2048):
            m.feed(samples[i:i + 2048])
        got = m.flush()
        if got != msg:
            bad.append(f"live Morse (sent {msg!r}, got {got!r})")
        if REGISTRY["morse-audio"].action(p).text != msg:
            bad.append("file Morse disagreed with live Morse")
    except Exception as exc:                                       # noqa: BLE001
        bad.append(f"live Morse ({type(exc).__name__}: {exc})")

    try:
        stop = threading.Event()
        last = None
        for res in REGISTRY["listen"].stream(
                stop, source="A file, played through",
                path=os.path.join(tmp, "dtmf.wav"), realtime=False,
                decode="DTMF touch-tones"):
            last = res
        if not last or "0123456789" not in (last.text or ""):
            bad.append("the live tool itself produced nothing")
    except Exception as exc:                                       # noqa: BLE001
        bad.append(f"live tool ({type(exc).__name__}: {exc})")

    return (not bad), ("; ".join(bad) if bad else
                       "4 SSTV modes, touch-tones and Morse all decoded from a stream; "
                       "file DTMF and spectrogram checked too")


def _sstv_check(tmp):
    """Encode a test card in every mode and decode it back."""
    try:
        import numpy as np
        from PIL import Image
    except ImportError as exc:
        return False, f"numpy/Pillow missing ({exc})"
    from .signals import MODES
    card, ref, w, h = _test_card(tmp)
    bad = []
    for name in MODES:
        try:
            enc = REGISTRY["sstv-encode"].action(card, mode=name, rate="22050")
            dec = REGISTRY["sstv-decode"].action(enc.file_path)
            got = np.asarray(Image.open(dec.image_path).convert("RGB")
                             .resize((w, h))).astype(float)
            err = float(np.abs(got - ref).mean())
            if dec.rows[0][1] != name or err > 12.0:
                bad.append(f"{name} (decoded as {dec.rows[0][1]}, error {err:.1f})")
            os.unlink(enc.file_path)
            os.unlink(dec.image_path)
        except Exception as exc:                                   # noqa: BLE001
            bad.append(f"{name} ({type(exc).__name__}: {exc})")
    return (not bad), ("; ".join(bad) if bad else f"{len(MODES)} modes round-tripped")


def _stego_check(tmp):
    """Hide a message in a picture, find it again, and prove the carver works."""
    try:
        import numpy as np
        from PIL import Image
    except ImportError as exc:
        return True, f"skipped: {exc}"
    rng = np.random.default_rng(11)
    src = os.path.join(tmp, "cover.png")
    Image.fromarray(rng.integers(0, 256, (180, 240, 3), dtype=np.uint8)).save(src)
    msg = "Meet at the bridge at nine. " * 9

    for bits, password in ((1, ""), (2, "hunter2"), (3, "")):
        out = REGISTRY["lsb-hide"].action(src, message=msg, password=password, bits=bits)
        back = REGISTRY["lsb-extract"].action(out.file_path, password=password)
        if back.text != msg:
            return False, f"LSB round trip failed at {bits} bit(s)"
    hidden = REGISTRY["lsb-hide"].action(src, message=msg, password="hunter2", bits=2)
    try:
        REGISTRY["lsb-extract"].action(hidden.file_path, password="wrong")
        return False, "a wrong password was accepted"
    except Exception:
        pass
    try:
        REGISTRY["lsb-extract"].action(src)
        return False, "it claimed to find a message in a clean image"
    except Exception:
        pass

    plane = REGISTRY["bitplane"].action(hidden.file_path, plane=0)
    if not plane.image_path or not os.path.exists(plane.image_path):
        return False, "the bit-plane viewer wrote nothing"

    poly = os.path.join(tmp, "poly.png")
    with open(poly, "wb") as fh:
        fh.write(open(hidden.file_path, "rb").read() + b"PK\x03\x04" + os.urandom(900))
    carved = REGISTRY["carve"].action(poly, extract=True, outdir=tmp)
    if not carved.warn or "past the end" not in carved.warn:
        return False, "appended data was not noticed"

    clean = REGISTRY["carve"].action(src)
    if clean.warn:
        return False, "a clean file was reported as carrying something"

    meta = REGISTRY["exif"].action(src, strip=True, outdir=tmp)
    if not meta.file_path or not os.path.exists(meta.file_path):
        return False, "the metadata stripper wrote nothing"

    zw = REGISTRY["zero-width"]
    for password in ("", "pw"):
        enc = zw.encode("the keys are under the mat", cover="Lunch at one?",
                        password=password)
        if "Lunch at one?" not in enc.text:
            return False, "the cover text was lost"
        if zw.decode(enc.text, password=password).text != "the keys are under the mat":
            return False, "zero-width round trip failed"
    return True, ""


def _radio_check(tmp):
    """Every digital mode, generated and decoded again - then again with noise."""
    try:
        import numpy as np
    except ImportError as exc:
        return True, f"skipped: {exc}"
    import wave

    from .signals import read_wav

    def noisy(src, snr_db, dst):
        x, rate = read_wav(src)
        power = float(np.mean(x ** 2))
        noise = np.random.default_rng(5).normal(
            0.0, (power / (10 ** (snr_db / 10.0))) ** 0.5, x.size)
        y = np.clip(x + noise, -1.0, 1.0)
        with wave.open(dst, "wb") as w:
            w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate)
            w.writeframes((y * 32000.0).astype("<i2").tobytes())
        return dst

    rtty_msg = "RYRY THE QUICK BROWN FOX 12345 (TEST) 599 73"
    made = REGISTRY["rtty-make"].action(rtty_msg, outdir=tmp)
    if REGISTRY["rtty"].action(made.file_path).text.strip() != rtty_msg:
        return False, "RTTY round trip failed"
    if REGISTRY["rtty"].action(noisy(made.file_path, 10, os.path.join(tmp, "r.wav"))
                              ).text.strip() != rtty_msg:
        return False, "RTTY failed at 10 dB signal-to-noise"

    psk_msg = "CQ CQ de M0ABC pse k 73"
    for carrier in (700.0, 1000.0, 1500.0):
        made = REGISTRY["psk31-make"].action(psk_msg, carrier=carrier, outdir=tmp)
        if psk_msg not in REGISTRY["psk31"].action(made.file_path).text:
            return False, f"PSK31 round trip failed on {carrier:g} Hz"
    if psk_msg not in REGISTRY["psk31"].action(
            noisy(made.file_path, 6, os.path.join(tmp, "p.wav"))).text:
        return False, "PSK31 failed at 6 dB signal-to-noise"

    info = "!5137.00N/00323.00W-Testing from Mountain Ash"
    made = REGISTRY["aprs-make"].action(info, source="M0ABC-9", via="WIDE1-1", outdir=tmp)
    got = REGISTRY["aprs"].action(made.file_path)
    if "M0ABC-9>APRS,WIDE1-1:" + info not in got.text:
        return False, f"AX.25 round trip failed: {got.text[:60]!r}"
    if "checksums good" not in got.note:
        return False, "the AX.25 checksum did not verify"
    if "51.61" not in str(got.rows):
        return False, "the APRS position was not read"
    if "M0ABC-9" not in REGISTRY["aprs"].action(
            noisy(made.file_path, 8, os.path.join(tmp, "a.wav"))).text:
        return False, "packet failed at 8 dB signal-to-noise"
    return True, ""


def _tokens_check(tmp):
    """The published test vectors where there are any, round trips where not."""
    import base64

    secret = base64.b32encode(b"12345678901234567890").decode()
    for when, want in (("59", "287082"), ("1111111109", "081804"),
                       ("1111111111", "050471"), ("1234567890", "005924")):
        got = REGISTRY["totp"].action(secret, at=when)
        if dict(got.rows)["Code now"] != want:
            return False, f"TOTP at {when} gave {dict(got.rows)['Code now']}, wanted {want}"
    fresh = REGISTRY["totp-new"].action(bits=160)
    if len(fresh.text) < 26:
        return False, "the generated TOTP secret is too short"

    jwt = REGISTRY["jwt"]
    token = jwt.encode('{"sub":"1234","name":"Dan"}', secret="k" * 32, alg="HS256")
    if "valid" != dict(jwt.decode(token.text, secret="k" * 32).rows)["Signature"]:
        return False, "a JWT it signed did not verify"
    if "NOT valid" not in dict(jwt.decode(token.text, secret="x" * 32).rows)["Signature"]:
        return False, "a JWT verified with the wrong key"
    unsigned = jwt.encode('{"admin":true}', alg="none")
    if "not signed at all" not in (jwt.decode(unsigned.text).warn or ""):
        return False, "an alg=none token was not flagged"

    sss = REGISTRY["shamir"]
    secret_text = "correct horse battery staple é"
    pieces = [p for p in sss.encode(secret_text, shares=5, threshold=3).text.split("\n\n") if p]
    if len(pieces) != 5:
        return False, "wrong number of shares"
    for take in ([0, 1, 2], [1, 3, 4], [0, 2, 4], [2, 3, 4]):
        if sss.decode("\n".join(pieces[i] for i in take)).text != secret_text:
            return False, f"shares {take} did not rebuild the secret"
    try:
        sss.decode("\n".join(pieces[:2]))
        return False, "two shares were accepted when three are needed"
    except Exception:
        pass

    folder = os.path.join(tmp, "manifest")
    os.makedirs(os.path.join(folder, "sub"), exist_ok=True)
    open(os.path.join(folder, "a.txt"), "w").write("hello")
    with open(os.path.join(folder, "sub", "b.bin"), "wb") as fh:
        fh.write(os.urandom(2048))
    made = REGISTRY["manifest"].action(folder)
    if dict(made.rows)["Files"] != 2:
        return False, "the manifest missed a file"
    if "All 2" not in REGISTRY["manifest-check"].action(folder).note:
        return False, "a fresh manifest did not verify"
    open(os.path.join(folder, "a.txt"), "w").write("tampered")
    after = REGISTRY["manifest-check"].action(folder)
    if "1 changed" not in after.note or not after.warn:
        return False, "a changed file was not noticed"
    return True, ""


def _enigma_check():
    """The published test vector, the no-self-encryption rule, and the solver."""
    from .enigma import Machine, crack

    m = Machine(("I", "II", "III"), (0, 0, 0), (0, 0, 0), "B", "")
    if m.run("A" * 25) != "BDZGOWCXLTKSBTMCDLPBMUQOF":
        return False, "the machine does not match the known test vector"

    plain = ("THEGERMANARMYUSEDTHISMACHINETOENCIPHEREVERYSIGNALITSENTANDBELIEVEDTHE"
             "TRAFFICWASCOMPLETELYSECUREBUTTHEWIRINGNEVERALLOWEDALETTERTOSTANDFOR"
             "ITSELFANDTHATSINGLEWEAKNESSGAVEBLETCHLEYPARKTHEWAYIN")
    for plugs in ("", "AB CD EF GH IJ"):
        machine = Machine(("IV", "II", "V"), (0, 4, 9), (16, 22, 4), "B", plugs)
        cipher = machine.run(plain)
        if any(a == b for a, b in zip(cipher, plain)):
            return False, "a letter encrypted to itself, which Enigma cannot do"
        back = Machine(("IV", "II", "V"), (0, 4, 9), (16, 22, 4), "B", plugs).run(cipher)
        if back != plain:
            return False, "the machine is not its own inverse"

    # ciphertext only, no plugboard: it should find the settings unaided
    cipher = Machine(("IV", "II", "V"), (0, 0, 0), (16, 22, 4), "B", "").run(plain)
    got = crack(cipher, ["I", "II", "III", "IV", "V"], "B", 4, known_rings=(0, 0, 0))
    if got["rotors"] != ("IV", "II", "V") or got["positions"] != (16, 22, 4):
        return False, f"the solver missed an unplugged message: {got['rotors']} {got['positions']}"

    # with five cables it needs the crib, which is the historical answer too
    cipher = Machine(("IV", "II", "V"), (0, 0, 0), (16, 22, 4), "B",
                     "AB CD EF GH IJ").run(plain)
    got = crack(cipher, ["I", "II", "III", "IV", "V"], "B", 8,
                crib="THEGERMANARMYUSEDTHIS", crib_window=6, known_rings=(0, 0, 0))
    if got["plaintext"] != plain:
        return False, "the crib attack failed on a five-cable message"
    return True, ""


def _interop_check(tmp):
    """age and the key/certificate format tools - all pure cryptography+stdlib."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization as ser, hashes
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime

    age = REGISTRY["age"]
    kp = REGISTRY["age-keygen"].action()
    lines = [l for l in kp.text.split("\n") if l.strip()]
    secret, pub = lines[0], lines[1]
    if not (pub.startswith("age1") and secret.startswith("AGE-SECRET-KEY-1")):
        return False, "age-keygen produced malformed keys"
    for msg in (b"", b"the eagle lands at dawn", bytes(range(256)) * 40):
        enc = age.encode(msg, recipient=pub)
        got = age.decode(enc.text, identity=secret)
        back = got.data if got.data is not None else got.text.encode()
        if back != msg:
            return False, f"age recipient round trip failed at {len(msg)} bytes"
    pw = age.decode(age.encode(b"secret via passphrase", passphrase="pw1").text,
                    passphrase="pw1")
    if pw.text != "secret via passphrase":
        return False, "age passphrase round trip failed"
    try:
        other = [l for l in REGISTRY["age-keygen"].action().text.split("\n") if l.strip()][0]
        age.decode(age.encode(b"x", recipient=pub).text, identity=other)
        return False, "age accepted the wrong identity"
    except Exception:
        pass

    # convert-key: PEM<->DER round trip and public extraction
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                ser.NoEncryption())
    conv = REGISTRY["convert-key"].action
    der = conv(key_pem, target="DER (binary)").data
    if b"PRIVATE KEY" not in conv(der, target="PEM (standard)").text.encode():
        return False, "convert-key PEM/DER round trip failed"
    if "PUBLIC KEY" not in conv(key_pem, target="public key only").text:
        return False, "convert-key public extraction failed"

    # pkcs12 build + open
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "selftest.local")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2026, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(ser.Encoding.PEM)
    p12 = REGISTRY["pkcs12"]
    built = p12.encode(key_pem, cert=cert_pem, password="pw", name="t")
    opened = p12.decode(built.data, password="pw")
    if "PRIVATE KEY" not in opened.text or "CERTIFICATE" not in opened.text:
        return False, "PKCS#12 build/open round trip failed"
    try:
        p12.decode(built.data, password="wrong")
        return False, "PKCS#12 accepted the wrong password"
    except Exception:
        pass
    return True, ""


def _qr_check(tmp):
    try:
        import segno  # noqa: F401
    except ImportError:
        return True, "skipped: segno not installed in this environment"
    # short input is exactly the case make() would turn into an unscannable
    # Micro QR, so check a short string and confirm it is a full QR
    out = REGISTRY["qr"].encode("age1qz", error="M", scale=4, outdir=tmp)
    if not out.file_path or not os.path.getsize(out.file_path):
        return False, "QR generation wrote nothing"
    version = dict(out.rows).get("QR version")
    if isinstance(version, str) and version.upper().startswith("M"):
        return False, "QR generator produced a Micro QR - phones cannot scan those"
    q = segno.make_qr("age1qz")
    if getattr(q, "is_micro", False):
        return False, "segno still yielding Micro QR"
    return True, f"full QR (version {version}), scannable"


def _signals2_check(tmp):
    """DTMF generation round trip, audio LSB stego, whitespace stego, detection."""
    try:
        import numpy as np
    except ImportError as exc:
        return True, f"skipped: {exc}"
    import os
    import wave

    # DTMF generate -> decode
    made = REGISTRY["dtmf-make"].action("0800123456#*ABCD", outdir=tmp)
    if REGISTRY["dtmf"].action(made.file_path).text != "0800123456#*ABCD":
        return False, "DTMF generate/decode round trip failed"

    # audio stego
    rate = 22050
    sig = (np.sin(2 * np.pi * 440 * np.arange(rate * 3) / rate) * 20000).astype("<i2")
    wav = os.path.join(tmp, "clip.wav")
    with wave.open(wav, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate)
        w.writeframes(sig.tobytes())
    msg = "audio stego round trip test " * 6
    h = REGISTRY["audio-hide"].action(wav, message=msg, password="pw")
    if REGISTRY["audio-extract"].action(h.file_path, password="pw").text != msg:
        return False, "audio LSB round trip failed"
    try:
        REGISTRY["audio-extract"].action(wav)
        return False, "audio extractor found a message in a clean file"
    except Exception:
        pass

    # whitespace stego
    ws = REGISTRY["whitespace"]
    cover = "line one\nline two\nline three\nline four"
    enc = ws.encode("hidden in the spaces", cover=cover, password="k")
    if ws.decode(enc.text, password="k").text != "hidden in the spaces":
        return False, "whitespace round trip failed"
    visible = [l.rstrip() for l in enc.text.split("\n")]
    if visible[:len(cover.split("\n"))] != cover.split("\n"):
        return False, "whitespace changed the visible cover text"

    # detection: clean vs embedded
    try:
        from PIL import Image
    except ImportError:
        return True, "stego-detect skipped: Pillow missing"
    rng = np.random.default_rng(4)
    grad = np.stack([np.tile(np.linspace(0, 255, 320), (240, 1))] * 3, -1).astype(np.uint8)
    clean = os.path.join(tmp, "clean.png")
    Image.fromarray(grad).save(clean)
    if REGISTRY["stego-detect"].action(clean).warn:
        return False, "stego-detect cried wolf on a clean image"
    big = os.path.join(tmp, "cover2.png")
    Image.fromarray(rng.integers(0, 256, (320, 400, 3), dtype=np.uint8)).save(big)
    hidden = REGISTRY["lsb-hide"].action(big, message="z" * 40000, password="k", bits=1)
    if not REGISTRY["stego-detect"].action(hidden.file_path).warn:
        return False, "stego-detect missed a heavily embedded image"
    return True, ""
