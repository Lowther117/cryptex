"""Hashes, HMACs and checksums — fingerprints, not encryption."""
from __future__ import annotations

import hashlib
import hmac
import os
import zlib

from .core import (Param, Result, ToolError, b64_any, need, to_bytes, to_text,
                   tool)

CAT = "Hashing"

ALGOS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512",
         "sha3_256", "sha3_512", "blake2b", "blake2s", "shake_256"]
BROKEN = {"md5": "MD5 is broken — two different files can be made to share a digest. "
                 "Fine for spotting accidental corruption, useless against a deliberate forgery.",
          "sha1": "SHA-1 is broken in the same way (a real collision was published in 2017). "
                  "Do not use it for signatures or integrity against an attacker."}
HASH_EXPLAIN = (
    "A hash turns any amount of data into a short fixed-length fingerprint. The same input "
    "always gives the same fingerprint; a one-character change gives a completely different "
    "one; and you cannot work backwards from the fingerprint to the data.\n\n"
    "That makes hashes right for checking that a download arrived intact, for comparing two "
    "files without sending them, and (with a slow password hash) for storing passwords. It "
    "makes them wrong for anything you need to get back — a hash is not encryption and has "
    "no 'decrypt' button anywhere, in this app or any other.")


def _digest(raw: bytes, algo: str) -> str:
    if algo == "crc32":
        return format(zlib.crc32(raw) & 0xFFFFFFFF, "08x")
    if algo == "adler32":
        return format(zlib.adler32(raw) & 0xFFFFFFFF, "08x")
    h = hashlib.new(algo)
    h.update(raw)
    return h.hexdigest(32) if algo.startswith("shake") else h.hexdigest()


tool(id="hash-text", name="Hash text", category=CAT,
     summary="Every common digest of whatever you paste in",
     explain=HASH_EXPLAIN,
     tags=["md5", "sha256", "digest", "checksum", "fingerprint"],
     params=[Param("algos", "Algorithms", "choice", "all common",
                   choices=["all common"] + ALGOS + ["crc32", "adler32"])],
     action=lambda d, algos="all common": _hash_text(d, algos),
     action_label="Hash", binary_ok=True)


def _hash_text(data, algos):
    raw = to_bytes(data)
    names = (ALGOS + ["crc32", "adler32"]) if algos == "all common" else [algos]
    rows = [(n.upper().replace("_", "-"), _digest(raw, n), len(_digest(raw, n)) * 4) for n in names]
    warn = " ".join(BROKEN[n] for n in names if n in BROKEN)
    return Result(rows=rows, headers=["Algorithm", "Digest (hex)", "Bits"],
                  text="\n".join(f"{r[0]:<12} {r[1]}" for r in rows),
                  note=f"{len(raw)} bytes hashed.", warn=warn)


tool(id="hash-file", name="Hash a file", category=CAT,
     summary="Checksum a file on disk and optionally verify it",
     explain=("Reads the file in chunks so size is no object. Paste the checksum you were "
              "given into the verify box and Cryptex will tell you plainly whether it matches "
              "— which is the whole point of publishing a checksum next to a download."),
     tags=["checksum", "verify", "sha256sum", "integrity"],
     input_kind="file", input_label="File",
     params=[Param("algo", "Algorithm", "choice", "sha256", choices=ALGOS + ["crc32", "adler32"]),
             Param("expected", "Expected checksum (optional)", "text", "", width=40)],
     action=lambda path, algo="sha256", expected="": _hash_file(path, algo, expected),
     action_label="Hash file")


def _hash_file(path, algo, expected):
    path = need(path, "Pick a file first.")
    if not os.path.isfile(path):
        raise ToolError(f"Not a file: {path}")
    if algo in ("crc32", "adler32"):
        fn, val = (zlib.crc32, 0) if algo == "crc32" else (zlib.adler32, 1)
        with open(path, "rb") as fh:
            while chunk := fh.read(1 << 20):
                val = fn(chunk, val)
        digest = format(val & 0xFFFFFFFF, "08x")
    else:
        h = hashlib.new(algo)
        with open(path, "rb") as fh:
            while chunk := fh.read(1 << 20):
                h.update(chunk)
        digest = h.hexdigest(32) if algo.startswith("shake") else h.hexdigest()
    size = os.path.getsize(path)
    res = Result(text=digest,
                 rows=[("File", os.path.basename(path)), ("Size", f"{size:,} bytes"),
                       ("Algorithm", algo), (algo, digest)],
                 headers=["", ""], note=f"{algo} of {os.path.basename(path)}")
    exp = "".join(expected.split()).lower()
    if exp:
        if hmac.compare_digest(exp, digest.lower()):
            res.note = "MATCH — the file is exactly what the checksum says it should be."
        else:
            res.warn = ("NO MATCH. The file is not the one that checksum describes — "
                        "it is corrupt, truncated, or a different file altogether.")
    if algo in BROKEN:
        res.warn = (res.warn + " " + BROKEN[algo]).strip()
    return res


tool(id="hmac", name="HMAC", category=CAT,
     summary="A hash with a shared secret mixed in — proves who sent it",
     explain=("A plain hash proves a message was not corrupted. It does not prove who sent it, "
              "because anyone can recompute it. An HMAC folds a shared secret key into the "
              "hash, so only someone with the key can produce a valid tag.\n\n"
              "This is what signs webhooks (Stripe, GitHub), API requests and session cookies. "
              "Compare tags with a constant-time comparison — this tool does."),
     tags=["signature", "webhook", "api", "mac", "authentication"],
     params=[Param("key", "Secret key", "password", ""),
             Param("key_format", "Key is", "choice", "auto",
                   choices=["auto", "text", "hex", "base64"],
                   help="Auto works it out from the shape of the key."),
             # HMAC needs a fixed-length digest, which rules out SHAKE
             Param("algo", "Algorithm", "choice", "sha256",
                   choices=[a for a in ALGOS if not a.startswith("shake")]),
             Param("expected", "Expected tag (optional)", "text", "", width=40)],
     action=lambda d, key="", key_format="auto", algo="sha256", expected="":
         _hmac(d, key, key_format, algo, expected),
     action_label="Compute HMAC", binary_ok=True)


def _key_bytes(key, fmt):
    from .core import decode_as
    return decode_as(key, fmt)[0]


def _hmac(data, key, key_format, algo, expected):
    from .core import decode_as
    kb, used = decode_as(need(key, "HMAC needs a secret key."), key_format)
    tag = hmac.new(kb, to_bytes(data), algo).hexdigest()
    res = Result(text=tag, rows=[("Algorithm", f"HMAC-{algo.upper()}"),
                                 ("Key read as", used),
                                 ("Key length", f"{len(kb)} bytes"), ("Tag", tag)],
                 headers=["", ""])
    exp = "".join(expected.split()).lower()
    if exp:
        if hmac.compare_digest(exp, tag):
            res.note = "VALID — the tag matches, so the message came from someone holding the key and was not altered."
        else:
            res.warn = "INVALID — the tag does not match. Treat the message as untrusted."
    return res


tool(id="password-hash", name="Password hashing (PBKDF2 / scrypt)", category=CAT,
     summary="Deliberately slow hashing — the right way to store a password",
     explain=("Ordinary hashes are fast, which is exactly wrong for passwords: a modern GPU "
              "tries billions of SHA-256 guesses a second. Password hashes are built to be "
              "slow and memory-hungry, and each one gets its own random salt so two people "
              "with the same password get different stored values.\n\n"
              "Argon2id is the current first choice, scrypt a good second, PBKDF2 the one "
              "that is available everywhere and accepted by every auditor. The output here is "
              "in the usual $algorithm$parameters$salt$hash shape so it can be stored as-is."),
     security="Never store a password with MD5, SHA-1 or a plain SHA-256. Use one of these.",
     tags=["pbkdf2", "scrypt", "argon2", "bcrypt", "salt", "kdf"],
     params=[Param("algo", "Algorithm", "choice", "pbkdf2-sha256",
                   choices=["pbkdf2-sha256", "pbkdf2-sha512", "scrypt", "argon2id (if installed)"]),
             Param("iterations", "Iterations / cost", "int", 600000,
                   help="OWASP suggests 600,000 for PBKDF2-SHA256. scrypt uses this as N, rounded to a power of two."),
             Param("salt", "Salt (blank = random)", "text", "", width=24),
             Param("verify", "Verify against this stored hash", "text", "", width=40)],
     action=lambda d, algo="pbkdf2-sha256", iterations=600000, salt="", verify="":
         _pwhash(to_text(d), algo, int(iterations), salt, verify),
     action_label="Hash password")


def _pwhash(password, algo, iterations, salt, verify):
    from .core import clamp
    import base64 as _b64
    iterations = clamp(iterations, 1000, 50_000_000, 600_000)
    if verify.strip():
        return _pwverify(password, verify.strip())
    if not password:
        raise ToolError("Type the password in the input box.")
    salt_b = salt.encode() if salt else os.urandom(16)
    if algo.startswith("argon2"):
        try:
            from argon2 import PasswordHasher
        except ImportError as exc:
            raise ToolError("argon2-cffi is not installed. Run: pip install argon2-cffi "
                            "(the build scripts install it for you).") from exc
        out = PasswordHasher().hash(password)
        return Result(text=out, note="Argon2id — salt and parameters are inside the string.")
    if algo == "scrypt":
        # N must be a power of two; clamp it so a big PBKDF2 iteration count
        # does not ask OpenSSL for half a gigabyte and get refused.
        n = 1 << min(17, max(14, (iterations).bit_length() - 1))
        dk = hashlib.scrypt(password.encode(), salt=salt_b, n=n, r=8, p=1, dklen=32,
                            maxmem=n * 8 * 128 * 3)
        out = f"$scrypt$n={n},r=8,p=1${_b64.b64encode(salt_b).decode()}${_b64.b64encode(dk).decode()}"
        return Result(text=out, note=f"scrypt N={n}, r=8, p=1. Memory use is about {n*8*128/1048576:.0f} MB.")
    digest = "sha256" if algo.endswith("256") else "sha512"
    dk = hashlib.pbkdf2_hmac(digest, password.encode(), salt_b, iterations)
    out = f"$pbkdf2-{digest}${iterations}${_b64.b64encode(salt_b).decode()}${_b64.b64encode(dk).decode()}"
    return Result(text=out, note=f"PBKDF2-HMAC-{digest.upper()}, {iterations:,} iterations. "
                                 "Store the whole string; it carries its own salt and cost.")


def _pwverify(password, stored):
    import base64 as _b64
    if stored.startswith("$argon2"):
        try:
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError
        except ImportError as exc:
            raise ToolError("argon2-cffi is not installed.") from exc
        try:
            PasswordHasher().verify(stored, password)
            return Result(note="MATCH — that is the right password.")
        except VerifyMismatchError:
            return Result(warn="NO MATCH — wrong password.")
    parts = stored.split("$")
    try:
        if stored.startswith("$scrypt$"):
            params = dict(kv.split("=") for kv in parts[2].split(","))
            salt = _b64.b64decode(parts[3])
            want = _b64.b64decode(parts[4])
            _n = int(params["n"])
            got = hashlib.scrypt(password.encode(), salt=salt, n=_n,
                                 r=int(params["r"]), p=int(params["p"]), dklen=len(want),
                                 maxmem=_n * 8 * 128 * 3)
        elif stored.startswith("$pbkdf2-"):
            digest = parts[1].split("-")[1]
            iters = int(parts[2])
            salt = _b64.b64decode(parts[3])
            want = _b64.b64decode(parts[4])
            got = hashlib.pbkdf2_hmac(digest, password.encode(), salt, iters, len(want))
        else:
            raise ToolError("Cryptex can verify $pbkdf2-…, $scrypt$… and $argon2… strings.")
    except (IndexError, ValueError, KeyError) as exc:
        raise ToolError(f"That stored hash is not in a shape Cryptex recognises ({exc}).") from exc
    if hmac.compare_digest(got, want):
        return Result(note="MATCH — that is the right password.")
    return Result(warn="NO MATCH — wrong password.")


tool(id="compare-files", name="Compare two files", category=CAT,
     summary="Are these two files byte-for-byte identical?",
     explain=("Hashes both files and compares. Faster and more certain than looking at file "
              "sizes and dates, and it works across machines: hash a file here, hash it there, "
              "compare the two strings."),
     tags=["identical", "duplicate", "verify"],
     input_kind="file", input_label="First file",
     params=[Param("other", "Second file", "file", "")],
     action=lambda path, other="": _compare_files(path, other), action_label="Compare")


def _compare_files(a, b):
    a = need(a, "Pick the first file.")
    b = need(b, "Pick the second file.")
    ha, hb = _hash_file(a, "sha256", "").text, _hash_file(b, "sha256", "").text
    sa, sb = os.path.getsize(a), os.path.getsize(b)
    rows = [(os.path.basename(a), f"{sa:,} bytes", ha), (os.path.basename(b), f"{sb:,} bytes", hb)]
    if ha == hb:
        return Result(rows=rows, headers=["File", "Size", "SHA-256"],
                      note="IDENTICAL — same bytes, whatever the names or dates say.")
    return Result(rows=rows, headers=["File", "Size", "SHA-256"],
                  warn="DIFFERENT — these are not the same file.")


# --------------------------------------------------------------------------
# Dictionary hash cracking
# --------------------------------------------------------------------------

_COMMON_PW = """
password 123456 123456789 12345678 12345 1234567 qwerty abc123 111111 123123
password1 1234567890 000000 iloveyou 1234 admin welcome monkey login football
princess dragon sunshine master hello letmein shadow superman qazwsx michael
password123 000000 qwerty123 zaq12wsx 1q2w3e4r trustno1 654321 555555 lovely
7777777 888888 121212 654321 batman passw0rd baseball access flower google
whatever hottie loveme secret summer hunter2 test test123 root toor changeme
ninja azerty solo starwars cheese computer soccer jordan michelle daniel
liverpool jessica pepper 11111111 andrew tigger 123qwe q1w2e3r4 charlie robert
thomas hockey ranger buster thomas harley hannah maggie ginger freedom banana
""".split()

_HASH_BY_LEN = {32: ["md5"], 40: ["sha1"], 56: ["sha224"], 64: ["sha256"],
                96: ["sha384"], 128: ["sha512"]}
_LEET = str.maketrans("aAeEiIoOsStTlLbBgG", "443311005577118866")


def _mangle(word):
    """A modest rule set - what a real password list tries first."""
    seen = set()
    bases = {word, word.lower(), word.upper(), word.capitalize(),
             word.lower().translate(_LEET)}
    for b in list(bases):
        for cand in (b, b + "!", b + "1", b + "123", b + "?", b + ".",
                     "!" + b, b + "12", b + "2", b + "2024", b + "2025"):
            if cand not in seen:
                seen.add(cand)
                yield cand
        for n in range(100):
            cand = f"{b}{n}"
            if cand not in seen:
                seen.add(cand)
                yield cand


def _hash_crack(data, algo="auto", wordlist="", **_k):
    digest = "".join(to_text(data).split()).lower()
    if not digest:
        raise ToolError("Paste the hash you want to crack.")
    if not all(c in "0123456789abcdef" for c in digest):
        raise ToolError("That does not look like a hex hash. This cracks unsalted hex "
                        "digests (MD5, SHA-1, SHA-256 and the like) - not bcrypt or Argon2, "
                        "which are built to resist exactly this.")
    if algo == "auto":
        algos = _HASH_BY_LEN.get(len(digest))
        if not algos:
            raise ToolError(f"A {len(digest)*4}-bit hash is not one Cryptex recognises by "
                            "length. Pick the algorithm by hand.")
    else:
        algos = [algo]

    words = [w for w in to_text(wordlist).split() if w] if wordlist.strip() else []
    words = words + _COMMON_PW
    # de-dup preserving order
    seen, ordered = set(), []
    for w in words:
        if w not in seen:
            seen.add(w); ordered.append(w)

    tried = 0
    for a in algos:
        try:
            hashlib.new(a)
        except Exception:
            continue
        for word in ordered:
            for cand in _mangle(word):
                tried += 1
                if hashlib.new(a, cand.encode("utf-8", "replace")).hexdigest() == digest:
                    return Result(text=cand,
                                  rows=[("Cracked", cand), ("Algorithm", a),
                                        ("Candidates tried", f"{tried:,}")],
                                  headers=["", ""], prefer="text",
                                  note=f"Found it: the {a.upper()} hash is \"{cand}\".")
    return Result(rows=[("Result", "not found"),
                        ("Algorithm(s) tried", ", ".join(algos)),
                        ("Candidates tried", f"{tried:,}")],
                  headers=["", ""],
                  warn="No match in the built-in list, even with mangling rules. Paste your "
                       "own wordlist to try more - or the password simply is not a common "
                       "one, which is the whole point of a good password.")


tool(id="hash-crack", name="Crack a hash (dictionary)", category=CAT,
     summary="Recover the text behind a plain hash using a wordlist and rules",
     explain=(
         "A plain hash like MD5 or SHA-256 is not encryption - there is no key to recover. "
         "The only way back is to guess the input, hash each guess and look for a match. This "
         "does exactly that: it runs a built-in list of the most common passwords and words, "
         "each put through the mangling rules a real cracker tries first - capitalising, "
         "leet-speak (a->4, e->3), and tacking numbers and symbols on the end.\n\n"
         "It detects the hash type from its length, so usually you can just paste the hash. "
         "Paste your own wordlist as well to go further.\n\n"
         "This works precisely because MD5 and SHA-256 are fast, which is what makes them the "
         "wrong choice for storing passwords. It will get nowhere against bcrypt, scrypt or "
         "Argon2 - those are deliberately slow and salted, which is why the password-hash "
         "tool uses them. And it only cracks weak inputs: a genuinely random password will "
         "not be in any list."),
     example="SHA-256 of 'password1' - paste 0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e",
     tags=["hash", "crack", "dictionary", "wordlist", "md5", "sha256", "brute force", "ctf"],
     params=[Param("algo", "Hash type", "choice", "auto",
                   choices=["auto", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"]),
             Param("wordlist", "Extra words (optional)", "multiline", "", width=30,
                   help="Your own candidate words, one per line, tried before the built-ins.")],
     action=_hash_crack, action_label="Crack it", input_kind="text")
