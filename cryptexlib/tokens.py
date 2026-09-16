"""Tokens, one-time codes and split secrets.

Four things that turn up constantly and are awkward to do by hand:

* **TOTP** - the six digits in an authenticator app. They are a hash of a
  shared secret and the clock, nothing more, and once you have seen that
  written down the whole thing stops being mysterious.
* **JWT** - the tokens that carry your login around a web application. They
  are not encrypted, only signed, which surprises people; this reads them,
  checks the signature and makes new ones.
* **Shamir's Secret Sharing** - splitting a secret into pieces so that any
  three of five rebuild it and any two reveal nothing at all. The real thing,
  not a key cut into chunks.
* **Checksum manifests** - the SHA256SUMS file, made and checked, for keeping
  a folder honest over time.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time

from .core import (Param, Result, ToolError, clamp, need, to_bytes, to_text,
                   tool)

CAT = "Tokens & secrets"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64url(text: str) -> bytes:
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------
# TOTP / HOTP
# --------------------------------------------------------------------------

_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _b32_secret(text: str) -> bytes:
    clean = "".join(c for c in text.upper() if c in _B32)
    if not clean:
        raise ToolError("That is not a valid secret. Authenticator secrets are "
                        "base32 - letters A-Z and digits 2-7.")
    pad = "=" * (-len(clean) % 8)
    try:
        return base64.b32decode(clean + pad)
    except Exception:
        raise ToolError("That secret is not valid base32.")


def _code(secret: bytes, counter: int, digits: int, algo: str) -> str:
    mac = hmac.new(secret, struct.pack(">Q", counter),
                   getattr(hashlib, algo.lower().replace("-", ""))).digest()
    off = mac[-1] & 0x0F
    value = struct.unpack_from(">I", mac, off)[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def _parse_uri(text):
    """otpauth://totp/Issuer:name?secret=...&digits=6&period=30 -> dict"""
    from urllib.parse import parse_qs, unquote, urlparse
    u = urlparse(text.strip())
    if u.scheme != "otpauth":
        return None
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    label = unquote(u.path.lstrip("/"))
    return {"label": label, "kind": u.netloc.lower(), **q}


def _totp(data, digits=6, period=30, algo="SHA1", at="", window=1, counter=-1):
    text = to_text(data).strip()
    label = ""
    parsed = _parse_uri(text) if text.lower().startswith("otpauth:") else None
    if parsed:
        label = parsed.get("label", "")
        text = parsed.get("secret", "")
        digits = int(parsed.get("digits", digits))
        period = int(parsed.get("period", period))
        algo = parsed.get("algorithm", algo).upper()
        if parsed.get("kind") == "hotp" and counter < 0:
            counter = int(parsed.get("counter", 0))
    secret = _b32_secret(text)
    digits = int(clamp(digits, 6, 10, 6))
    period = int(clamp(period, 1, 3600, 30))
    if algo.upper() not in ("SHA1", "SHA256", "SHA512"):
        raise ToolError("TOTP uses SHA1, SHA256 or SHA512.")

    if counter >= 0:
        code = _code(secret, int(counter), digits, algo)
        return Result(text=code,
                      rows=[("Code", code), ("Counter", counter),
                            ("Digits", digits), ("Algorithm", algo)],
                      headers=["", ""], prefer="text",
                      note="HOTP - counter based. The counter goes up by one each use.")

    when = time.time()
    if at.strip():
        when = _when(at)
    step = int(when // period)
    left = period - int(when % period)
    rows = []
    if label:
        rows.append(("Account", label))
    now = _code(secret, step, digits, algo)
    rows += [("Code now", now),
             ("Valid for", f"{left} more second{'s' if left != 1 else ''}"),
             ("Next code", _code(secret, step + 1, digits, algo)),
             ("Previous code", _code(secret, step - 1, digits, algo)),
             ("Time step", f"{step}  ({period}s periods since 1970)"),
             ("Digits / algorithm", f"{digits} / {algo}")]
    for w in range(2, int(clamp(window, 1, 10, 1)) + 1):
        rows.append((f"+{w} steps", _code(secret, step + w, digits, algo)))
    return Result(text=now, rows=rows, headers=["", ""], prefer="text",
                  note=f"Valid for {left} more seconds. The previous and next codes are "
                       "shown because servers normally accept one step either side to "
                       "allow for clocks being out.",
                  warn="Your computer's clock has to be right. If codes are rejected "
                       "everywhere, that is almost always why.")


def _when(text):
    text = text.strip()
    if text.isdigit():
        return float(text)
    import datetime as dt
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(text, fmt).replace(
                tzinfo=dt.timezone.utc).timestamp()
        except ValueError:
            pass
    raise ToolError("Give the time as 2026-09-14 17:30:00, or as a Unix timestamp.")


def _totp_secret(bits=160, issuer="Cryptex", account="me", digits=6, period=30):
    raw = secrets.token_bytes(int(clamp(bits, 80, 512, 160)) // 8)
    b32 = base64.b32encode(raw).decode().rstrip("=")
    from urllib.parse import quote
    uri = (f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={b32}"
           f"&issuer={quote(issuer)}&digits={int(digits)}&period={int(period)}")
    return Result(text=b32,
                  rows=[("Secret (base32)", b32),
                        ("Length", f"{len(raw) * 8} bits"),
                        ("Set-up URI", uri),
                        ("Code right now", _code(raw, int(time.time() // int(period)),
                                                 int(digits), "SHA1"))],
                  headers=["", ""], prefer="text",
                  note="Type the secret into an authenticator app, or turn the URI into a "
                       "QR code. Keep a copy somewhere safe - losing it locks you out.")


tool(id="totp", name="Authenticator codes (TOTP)", category=CAT,
     summary="Works out the six-digit code from a secret, at any point in time",
     explain=(
         "The codes in an authenticator app are not sent to you and are not random. Your "
         "phone and the server share one secret, both look at the clock, and both compute "
         "the same answer: take the number of thirty-second periods since 1970, run it "
         "through HMAC with the shared secret, and take six digits out of the result. That "
         "is the whole algorithm. No network involved, which is why it works in aeroplane "
         "mode.\n\n"
         "Paste a base32 secret, or the whole otpauth:// URI from behind a set-up QR code, "
         "and this gives you the code. It shows the previous and next ones too, because "
         "servers normally accept a step either side to allow for clock drift.\n\n"
         "Useful for recovering an account when you have the secret but not the phone, for "
         "checking a server's implementation, and for seeing what the code will be at some "
         "point in the future. Set a counter instead of a time and it does HOTP."),
     example="JBSWY3DPEHPK3PXP",
     tags=["totp", "hotp", "2fa", "mfa", "authenticator", "google authenticator", "otp"],
     params=[Param("digits", "Digits", "int", 6, minimum=6, maximum=10),
             Param("period", "Seconds per code", "int", 30, minimum=1, maximum=3600),
             Param("algo", "Algorithm", "choice", "SHA1",
                   choices=["SHA1", "SHA256", "SHA512"],
                   help="SHA1 in practice, whatever the documentation says."),
             Param("at", "At this time", "text", "", width=20,
                   help="Empty means now. Otherwise 2026-09-14 17:30:00, or a timestamp."),
             Param("window", "Also show ahead", "int", 1, minimum=1, maximum=10),
             Param("counter", "HOTP counter", "int", -1, minimum=-1, maximum=10 ** 9,
                   help="-1 for time-based. Anything else switches to counter-based HOTP.")],
     action=_totp, action_label="Get the code")


tool(id="totp-new", name="New authenticator secret", category=CAT,
     summary="Makes a fresh TOTP secret and the set-up URI for it",
     explain=(
         "Generates a random secret of the right shape to hand to an authenticator app, "
         "together with the otpauth:// URI that set-up QR codes contain.\n\n"
         "Useful if you are building something that needs two-factor login, or if you want "
         "a spare code generator you control. The standard length is 160 bits."),
     tags=["totp", "2fa", "secret", "generate", "authenticator", "enrol"],
     params=[Param("bits", "Secret length", "int", 160, minimum=80, maximum=512),
             Param("issuer", "Issuer", "text", "Cryptex", width=18),
             Param("account", "Account", "text", "me", width=18),
             Param("digits", "Digits", "int", 6, minimum=6, maximum=10),
             Param("period", "Seconds per code", "int", 30, minimum=1, maximum=3600)],
     input_kind="none", action=_totp_secret, action_label="Generate")


# --------------------------------------------------------------------------
# JSON Web Tokens
# --------------------------------------------------------------------------

_JWT_HMAC = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}


def _jwt_read(data, secret="", **_k):
    text = to_text(data).strip().strip('"')
    if text.lower().startswith("bearer "):
        text = text[7:].strip()
    parts = text.split(".")
    if len(parts) not in (2, 3):
        raise ToolError("A JWT is three base64 pieces separated by dots. This is not one.")
    try:
        head = json.loads(_unb64url(parts[0]))
        body = json.loads(_unb64url(parts[1]))
    except Exception:
        raise ToolError("The header or payload is not valid base64url JSON. If this is an "
                        "encrypted token (five parts, JWE) there is nothing to read "
                        "without the key.")
    alg = str(head.get("alg", "?"))
    rows = [("Algorithm", alg), ("Type", head.get("typ", "-"))]
    if head.get("kid"):
        rows.append(("Key id", head["kid"]))
    now = int(time.time())
    for key, label in (("iss", "Issuer"), ("sub", "Subject"), ("aud", "Audience"),
                       ("jti", "Token id"), ("scope", "Scope")):
        if key in body:
            rows.append((label, _brief(body[key])))
    warn = None
    for key, label in (("iat", "Issued"), ("nbf", "Not before"), ("exp", "Expires")):
        if key in body:
            rows.append((label, _stamp(body[key], now)))
    if "exp" in body and isinstance(body["exp"], (int, float)) and body["exp"] < now:
        warn = "This token has expired."
    for k, v in body.items():
        if k not in ("iss", "sub", "aud", "jti", "scope", "iat", "nbf", "exp"):
            rows.append((k, _brief(v)))

    if alg.lower() == "none":
        warn = ("The algorithm is 'none' - this token is not signed at all. Anyone can "
                "write one. Any server that accepts it is broken.")
    elif secret and len(parts) == 3:
        ok, why = _jwt_check(parts, alg, secret)
        rows.append(("Signature", "valid" if ok else f"NOT valid - {why}"))
        if not ok and warn is None:
            warn = "The signature does not check out. Do not trust anything in this token."
    elif len(parts) == 3:
        rows.append(("Signature", "not checked - no key given"))

    pretty = json.dumps({"header": head, "payload": body}, indent=2, default=str)
    return Result(text=pretty, rows=rows, headers=["Field", "Value"], prefer="text",
                  note="Read. Remember a JWT is signed, not encrypted - everything in it "
                       "is public to whoever holds the token.",
                  warn=warn)


def _jwt_check(parts, alg, secret):
    signing = (parts[0] + "." + parts[1]).encode()
    try:
        sig = _unb64url(parts[2])
    except Exception:
        return False, "the signature is not valid base64url"
    if alg in _JWT_HMAC:
        want = hmac.new(to_bytes(secret), signing, _JWT_HMAC[alg]).digest()
        return hmac.compare_digest(sig, want), "wrong key, or the token was altered"
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding
        key = serialization.load_pem_public_key(to_bytes(secret))
    except Exception:
        return False, f"{alg} needs the PEM public key, and that is not one"
    h = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}.get(
        alg[-3:], hashes.SHA256())
    try:
        if alg.startswith("RS"):
            key.verify(sig, signing, padding.PKCS1v15(), h)
        elif alg.startswith("PS"):
            key.verify(sig, signing, padding.PSS(padding.MGF1(h),
                                                 padding.PSS.MAX_LENGTH), h)
        elif alg.startswith("ES"):
            from cryptography.hazmat.primitives.asymmetric.utils import \
                encode_dss_signature
            half = len(sig) // 2
            der = encode_dss_signature(int.from_bytes(sig[:half], "big"),
                                       int.from_bytes(sig[half:], "big"))
            key.verify(der, signing, ec.ECDSA(h))
        else:
            return False, f"{alg} is not supported here"
        return True, ""
    except Exception:
        return False, "wrong key, or the token was altered"


def _stamp(v, now):
    try:
        import datetime as dt
        when = dt.datetime.fromtimestamp(float(v), dt.timezone.utc)
        delta = float(v) - now
        ago = f"{abs(delta) / 60:.0f} min" if abs(delta) < 7200 else \
              f"{abs(delta) / 3600:.1f} h" if abs(delta) < 172800 else \
              f"{abs(delta) / 86400:.1f} days"
        return f"{when:%Y-%m-%d %H:%M:%S} UTC  ({ago} {'ago' if delta < 0 else 'from now'})"
    except Exception:
        return str(v)


def _brief(v, n=70):
    s = v if isinstance(v, str) else json.dumps(v, default=str)
    return s if len(s) <= n else s[:n] + "..."


def _jwt_make(data, secret="", alg="HS256", expires_in=3600, **_k):
    body_text = to_text(data).strip() or "{}"
    try:
        body = json.loads(body_text)
    except Exception:
        raise ToolError("The payload has to be JSON, e.g.  "
                        '{"sub": "1234", "name": "Dan", "admin": true}')
    if not isinstance(body, dict):
        raise ToolError("The payload has to be a JSON object.")
    now = int(time.time())
    body.setdefault("iat", now)
    if int(expires_in) > 0:
        body.setdefault("exp", now + int(expires_in))
    head = {"alg": alg, "typ": "JWT"}
    signing = _b64url(json.dumps(head, separators=(",", ":")).encode()) + "." + \
        _b64url(json.dumps(body, separators=(",", ":")).encode())
    if alg == "none":
        token = signing + "."
        warn = "Unsigned. This is only useful for testing what a server does with it."
    elif alg in _JWT_HMAC:
        need(secret, "An HMAC token needs a signing key. Type one.")
        sig = hmac.new(to_bytes(secret), signing.encode(), _JWT_HMAC[alg]).digest()
        token = signing + "." + _b64url(sig)
        warn = None if len(to_bytes(secret)) >= 32 else \
            ("That key is short. HS256 should be signed with at least 32 random bytes - "
             "a guessable key means anyone can mint tokens.")
    else:
        raise ToolError("Making RS/ES/PS tokens is not supported here - use the signing "
                        "tool with the private key. HS256, HS384, HS512 and none work.")
    return Result(text=token,
                  rows=[("Algorithm", alg), ("Length", f"{len(token)} characters"),
                        ("Expires", _stamp(body["exp"], now) if "exp" in body else "never")],
                  headers=["", ""], prefer="text",
                  note="Signed. Anyone can read the contents; only someone with the key "
                       "can make a valid one.", warn=warn)


tool(id="jwt", name="JSON Web Token (JWT)", category=CAT,
     summary="Reads, checks and creates the tokens web logins run on",
     explain=(
         "A JWT is three base64 pieces joined by dots: a header saying how it was signed, a "
         "payload of claims, and a signature over the first two. It is what sits behind "
         "most 'Authorization: Bearer ...' headers.\n\n"
         "The thing people get wrong: **it is signed, not encrypted**. The payload is "
         "base64, not ciphertext. Anyone holding the token can read every claim in it, so "
         "nothing private belongs in one.\n\n"
         "Paste one in and this decodes it, lays out the claims, and works out in plain "
         "words when it was issued and when it expires. Give it the key as well and it "
         "checks the signature - HMAC with the shared secret, or RSA/ECDSA with the PEM "
         "public key.\n\n"
         "It also flags the classic hole: a token whose algorithm is 'none'. A server that "
         "trusts the header to tell it how to verify can be handed an unsigned token and "
         "will accept it.\n\n"
         "Switch to Create and it will mint one from a JSON payload."),
     example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.<signature>",
     tags=["jwt", "json web token", "bearer", "oauth", "auth", "token", "hs256"],
     params=[Param("secret", "Key", "text", "", width=34,
                   help="The shared secret for HS*, or a PEM public key for RS/ES/PS. "
                        "Leave empty to decode without checking."),
             Param("alg", "Algorithm", "choice", "HS256", only="encode",
                   choices=["HS256", "HS384", "HS512", "none"]),
             Param("expires_in", "Expires in (seconds)", "int", 3600, only="encode",
                   minimum=0, maximum=10 ** 8, help="0 for no expiry.")],
     encode=_jwt_make, decode=_jwt_read,
     encode_label="Create", decode_label="Read & check")


# --------------------------------------------------------------------------
# Shamir's Secret Sharing
# --------------------------------------------------------------------------

_P = (1 << 521) - 1     # a Mersenne prime, comfortably larger than any secret here


def _eval(coeffs, x, p):
    y = 0
    for c in reversed(coeffs):
        y = (y * x + c) % p
    return y


def _split(data, shares=5, threshold=3, **_k):
    raw = to_bytes(data)
    if not raw:
        raise ToolError("Type the secret to split - a password, a key, a seed phrase.")
    shares = int(clamp(shares, 2, 255, 5))
    threshold = int(clamp(threshold, 2, shares, 3))
    if threshold > shares:
        raise ToolError("You cannot need more pieces than you make.")
    chunk = (_P.bit_length() - 1) // 8 - 1        # bytes that always fit under the prime
    blocks = [raw[i:i + chunk] for i in range(0, len(raw), chunk)]
    out = {i: [] for i in range(1, shares + 1)}
    for block in blocks:
        value = int.from_bytes(b"\x01" + block, "big")     # leading 1 keeps zero bytes
        coeffs = [value] + [secrets.randbelow(_P) for _ in range(threshold - 1)]
        for x in range(1, shares + 1):
            out[x].append(_eval(coeffs, x, _P))
    lines = []
    for x in range(1, shares + 1):
        body = b"".join(v.to_bytes(66, "big") for v in out[x])
        lines.append(f"{threshold}-{x}-" + base64.b32encode(body).decode().rstrip("="))
    return Result(text="\n\n".join(lines),
                  rows=[("Pieces made", shares), ("Needed to rebuild", threshold),
                        ("Secret length", f"{len(raw)} bytes"),
                        ("Blocks", len(blocks))],
                  headers=["", ""], prefer="text",
                  note=f"Any {threshold} of these {shares} rebuild the secret. Any "
                       f"{threshold - 1} tell you nothing whatsoever - not even its length "
                       "to better than a block. Give them to different people or put them "
                       "in different places.",
                  warn="Every piece begins with the threshold and its own number. Keep the "
                       "whole line, exactly as written.")


def _combine(data, **_k):
    text = to_text(data)
    pieces, threshold = [], None
    for line in text.replace(",", "\n").split("\n"):
        line = line.strip()
        if not line:
            continue
        bits = line.split("-", 2)
        if len(bits) != 3 or not bits[0].isdigit() or not bits[1].isdigit():
            raise ToolError(f"This does not look like a piece: {line[:30]}... "
                            "Each one starts like '3-1-' followed by base32.")
        t, x = int(bits[0]), int(bits[1])
        threshold = threshold or t
        if t != threshold:
            raise ToolError("These pieces are from different splits - their thresholds "
                            "do not match.")
        body = bits[2].strip()
        raw = base64.b32decode(body + "=" * (-len(body) % 8))
        if len(raw) % 66:
            raise ToolError("One of the pieces is the wrong length - it has been cut "
                            "short or had characters added.")
        pieces.append((x, [int.from_bytes(raw[i:i + 66], "big")
                           for i in range(0, len(raw), 66)]))
    if len(pieces) < 2:
        raise ToolError("Paste at least two pieces, one per line.")
    seen = {x for x, _ in pieces}
    if len(seen) != len(pieces):
        raise ToolError("The same piece has been pasted twice. They must all be different.")
    if len(pieces) < threshold:
        raise ToolError(f"These pieces need {threshold} to rebuild the secret and you "
                        f"have given {len(pieces)}.")
    pieces = pieces[:threshold]
    nblocks = len(pieces[0][1])
    if any(len(p[1]) != nblocks for _x, p in [(x, (x, v)) for x, v in pieces]):
        raise ToolError("The pieces are not all the same length.")
    out = b""
    for b in range(nblocks):
        total = 0
        for i, (xi, yi) in enumerate(pieces):
            num, den = 1, 1
            for j, (xj, _yj) in enumerate(pieces):
                if i == j:
                    continue
                num = (num * (-xj)) % _P
                den = (den * (xi - xj)) % _P
            total = (total + yi[b] * num * pow(den, _P - 2, _P)) % _P
        blob = total.to_bytes((total.bit_length() + 7) // 8 or 1, "big")
        if not blob or blob[0] != 1:
            raise ToolError("Those pieces do not go together - wrong set, or one of them "
                            "has been mistyped.")
        out += blob[1:]
    try:
        text_out = out.decode("utf-8")
    except UnicodeDecodeError:
        text_out = ""
    return Result(text=text_out, data=None if text_out else out,
                  rows=[("Pieces used", len(pieces)), ("Recovered", f"{len(out)} bytes")],
                  headers=["", ""], prefer="text",
                  note="Rebuilt.")


tool(id="shamir", name="Split a secret into pieces", category=CAT,
     summary="Any three of five rebuild it; any two reveal nothing",
     explain=(
         "Cutting a password into five chunks and handing them out is a bad idea: each "
         "chunk gives away a fifth of it, and you need every one back. Shamir's scheme "
         "does the job properly.\n\n"
         "The trick is that two points define a line, three define a parabola, and so on. "
         "Hide the secret as the constant term of a curve of degree two, hand out five "
         "points on that curve, and any three of them determine it exactly - while any two "
         "fit infinitely many curves equally well, so they say nothing at all. That is not "
         "'hard to break'; it is mathematically impossible to break, like a one-time pad.\n\n"
         "Good for a master password left with family, recovery keys for a company account, "
         "or a wallet seed split across locations. Every piece must be kept whole and "
         "exactly as written - it carries its own number and the threshold.\n\n"
         "Paste the pieces back in, one per line, to rebuild it."),
     example="correct horse battery staple",
     tags=["shamir", "secret sharing", "split", "sss", "threshold", "recovery", "backup"],
     params=[Param("shares", "Pieces to make", "int", 5, minimum=2, maximum=64,
                   only="encode"),
             Param("threshold", "Pieces needed", "int", 3, minimum=2, maximum=64,
                   only="encode", help="Fewer than this learn nothing at all.")],
     encode=_split, decode=_combine,
     encode_label="Split it", decode_label="Rebuild it")


# --------------------------------------------------------------------------
# Checksum manifests
# --------------------------------------------------------------------------

def _manifest(path, algo="sha256", recurse=True, save=True):
    path = need(path, "Pick a folder.")
    if not os.path.isdir(path):
        raise ToolError("Pick a folder, not a file.")
    algo = algo.lower()
    if algo not in hashlib.algorithms_available:
        raise ToolError(f"Unknown algorithm: {algo}")
    root = os.path.abspath(path)
    names = []
    for base, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for f in sorted(files):
            if f.startswith(".") or f.upper().endswith("SUMS"):
                continue
            names.append(os.path.relpath(os.path.join(base, f), root))
        if not recurse:
            break
    if not names:
        raise ToolError("No files in that folder.")
    lines, total = [], 0
    for rel in names:
        h = hashlib.new(algo)
        full = os.path.join(root, rel)
        with open(full, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                h.update(block)
        total += os.path.getsize(full)
        lines.append(f"{h.hexdigest()}  {rel.replace(os.sep, '/')}")
    body = "\n".join(lines) + "\n"
    dest = ""
    if save:
        dest = os.path.join(root, algo.upper() + "SUMS")
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(body)
    return Result(text=body, file_path=dest or None,
                  rows=[("Files", len(names)), ("Total size", f"{total:,} bytes"),
                        ("Algorithm", algo), ("Written to", dest or "(not saved)")],
                  headers=["", ""], prefer="text",
                  note=f"{len(names)} file(s) hashed."
                       + (f" Manifest written to {dest}." if dest else ""))


def _verify_manifest(path, algo="auto", **_k):
    path = need(path, "Pick the SUMS file to check against.")
    if os.path.isdir(path):
        for name in ("SHA256SUMS", "SHA512SUMS", "SHA1SUMS", "MD5SUMS", "BLAKE2BSUMS"):
            if os.path.isfile(os.path.join(path, name)):
                path = os.path.join(path, name)
                break
        else:
            raise ToolError("No SUMS file in that folder. Point at the manifest itself.")
    root = os.path.dirname(os.path.abspath(path))
    if algo == "auto":
        name = os.path.basename(path).upper()
        # BLAKE2B before SHA512: both are 128 hex characters, so the file name
        # is the only thing that tells them apart
        algo = next((a for a in ("BLAKE2B", "SHA512", "SHA256", "SHA1", "MD5") if a in name), "")
        if not algo:
            algo = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(
                len(open(path).readline().split()[0]), "")
        if not algo:
            raise ToolError("Cannot tell which hash this manifest uses. Choose it by hand.")
    algo = algo.lower()

    ok, bad, missing, extra = 0, [], [], []
    listed = set()
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        want, rel = parts[0].lower(), parts[1].lstrip("*").strip()
        listed.add(rel)
        full = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.isfile(full):
            missing.append(rel)
            continue
        h = hashlib.new(algo)
        with open(full, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                h.update(block)
        if h.hexdigest() == want:
            ok += 1
        else:
            bad.append(rel)
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            rel = os.path.relpath(os.path.join(base, f), root).replace(os.sep, "/")
            if rel not in listed and not f.upper().endswith("SUMS") and not f.startswith("."):
                extra.append(rel)

    rows = [("Matched", ok), ("Changed", len(bad)), ("Missing", len(missing)),
            ("Not in the manifest", len(extra)), ("Algorithm", algo)]
    for rel in bad[:25]:
        rows.append(("CHANGED", rel))
    for rel in missing[:25]:
        rows.append(("MISSING", rel))
    for rel in extra[:25]:
        rows.append(("NEW", rel))
    trouble = bad or missing
    return Result(rows=rows, headers=["", "File"],
                  note=(f"All {ok} file(s) match." if not trouble else
                        f"{ok} match, {len(bad)} changed, {len(missing)} missing."),
                  warn=None if not trouble else
                       "Some files do not match the manifest. If this is a download, get "
                       "it again. If it is your own folder, something has altered them.")


tool(id="manifest", name="Checksum manifest (SHA256SUMS)", category=CAT,
     summary="Hashes every file in a folder into one list you can check later",
     explain=(
         "A manifest is one line per file: the hash, two spaces, the name. It is the same "
         "SHA256SUMS file that ships beside Linux images and software releases, and the "
         "same format sha256sum -c reads, so anything you make here can be checked "
         "anywhere.\n\n"
         "What it is for: proving nothing in a folder has changed. Make one when a set of "
         "files is known good - a backup, a photo archive, a downloaded release - and "
         "checking it later tells you exactly which files have been altered, which have "
         "gone, and which have appeared since.\n\n"
         "It catches silent disk corruption as readily as tampering, which in practice is "
         "the more common of the two."),
     tags=["sha256sums", "manifest", "checksum", "integrity", "verify", "backup"],
     input_kind="folder", input_label="Folder",
     params=[Param("algo", "Algorithm", "choice", "sha256",
                   choices=["sha256", "sha512", "sha1", "md5", "blake2b"]),
             Param("recurse", "Include subfolders", "bool", True),
             Param("save", "Write the SUMS file into the folder", "bool", True)],
     action=_manifest, action_label="Make the manifest")


tool(id="manifest-check", name="Check a checksum manifest", category=CAT,
     summary="Verifies a folder against a SHA256SUMS file",
     explain=(
         "Point this at a SUMS file - or at the folder holding one - and it re-hashes "
         "everything and reports what matches, what has changed, what has gone missing and "
         "what has turned up since the manifest was made.\n\n"
         "It reads the standard format, so manifests published alongside downloads work "
         "here without modification."),
     tags=["sha256sums", "verify", "integrity", "check", "manifest"],
     input_kind="file", input_label="SUMS file (or its folder)",
     params=[Param("algo", "Algorithm", "choice", "auto",
                   choices=["auto", "sha256", "sha512", "sha1", "md5", "blake2b"])],
     action=_verify_manifest, action_label="Check them")
