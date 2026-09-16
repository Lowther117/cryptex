"""Interop - talking to the rest of the world in its own formats.

Everything else in Cryptex that encrypts uses its own CRYPTEX1 container, which
is fine when both ends run Cryptex and useless otherwise. The tools here speak
formats other software already understands:

* **age** - the modern file-encryption format (the successor to the "encrypt a
  file for a friend" job PGP used to do). Small keys that start ``age1``, no
  configuration, one obvious way to do each thing.
* **QR codes** - turn any output into a QR image, so a key, a one-time-password
  secret or a short message crosses to a phone without being typed.
* **Key and certificate conversion** - move a key between PEM and DER, pull the
  public half out of a private key, and build or open a ``.pfx``/``.p12`` bundle,
  which is how Windows and a lot of enterprise kit expect to be handed a key and
  its certificate together.
"""
from __future__ import annotations

import base64
import os

from .core import Param, Result, ToolError, clamp, need, to_bytes, to_text, tool

CAT = "Interop"


# --------------------------------------------------------------------------
# bech32 - the "age1..." address encoding (same checksum scheme as Bitcoin)
# --------------------------------------------------------------------------

_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_encode(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_B32[d] for d in data + checksum)


def _bech32_decode(text):
    text = text.strip()
    lower = text.lower()
    pos = lower.rfind("1")
    if pos < 1 or pos + 7 > len(text):
        raise ToolError("Not a valid age key - the bech32 separator is missing.")
    hrp = lower[:pos]
    try:
        data = [_B32.index(c) for c in lower[pos + 1:]]
    except ValueError:
        raise ToolError("Not a valid age key - it contains characters bech32 never uses.")
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
        raise ToolError("That age key fails its checksum - a character has been mistyped.")
    return hrp, data[:-6]


def _convertbits(data, frm, to, pad=True):
    acc, bits, out = 0, 0, []
    maxv = (1 << to) - 1
    for value in data:
        acc = (acc << frm) | value
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (to - bits)) & maxv)
    return out


# --------------------------------------------------------------------------
# age
# --------------------------------------------------------------------------

def _x25519():
    from cryptography.hazmat.primitives.asymmetric import x25519
    return x25519


def _hkdf(ikm, salt, info, length=32):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=info).derive(ikm)


def _b64(raw):
    return base64.b64encode(raw).decode().rstrip("=")


def _unb64(text):
    text = text.strip()
    return base64.b64decode(text + "=" * (-len(text) % 4))


def _age_keygen(**_k):
    x = _x25519()
    priv = x.X25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    raw_priv = priv.private_bytes(serialization.Encoding.Raw,
                                  serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
    raw_pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)
    pub = _bech32_encode("age", _convertbits(list(raw_pub), 8, 5))
    secret = _bech32_encode("age-secret-key-", _convertbits(list(raw_priv), 8, 5)).upper()
    return Result(text=secret + "\n\n" + pub,
                  rows=[("Public recipient", pub),
                        ("Secret identity", secret)],
                  headers=["", ""], prefer="text",
                  note="Give the public recipient (age1...) to anyone who wants to send "
                       "you a file. Keep the secret identity (AGE-SECRET-KEY-...) - it is "
                       "the only thing that opens what they send.",
                  warn="Anyone with the secret identity can read everything sent to you. "
                       "It is not recoverable if lost.")


def _age_pub_from_secret(secret):
    hrp, data = _bech32_decode(secret)
    if "secret-key" not in hrp:
        raise ToolError("That is a recipient (public) key, not a secret identity.")
    raw = bytes(_convertbits(data, 5, 8, pad=False))
    priv = _x25519().X25519PrivateKey.from_private_bytes(raw)
    return priv


def _age_recipient_raw(recipient):
    hrp, data = _bech32_decode(recipient)
    if hrp != "age":
        raise ToolError("That does not look like an age recipient (it should start 'age1').")
    return bytes(_convertbits(data, 5, 8, pad=False))


_AGE_STREAM_CHUNK = 64 * 1024


def _age_stream_key(file_key, nonce):
    return _hkdf(file_key, nonce, b"payload")


def _age_encrypt_payload(file_key, plaintext):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    nonce = os.urandom(16)
    key = _age_stream_key(file_key, nonce)
    aead = ChaCha20Poly1305(key)
    out = bytearray(nonce)
    chunks = [plaintext[i:i + _AGE_STREAM_CHUNK]
              for i in range(0, len(plaintext), _AGE_STREAM_CHUNK)] or [b""]
    for i, chunk in enumerate(chunks):
        last = i == len(chunks) - 1
        cnonce = i.to_bytes(11, "big") + (b"\x01" if last else b"\x00")
        out += aead.encrypt(cnonce, chunk, None)
    return bytes(out)


def _age_decrypt_payload(file_key, body):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    if len(body) < 16:
        raise ToolError("The age file is truncated.")
    nonce, body = body[:16], body[16:]
    aead = ChaCha20Poly1305(_age_stream_key(file_key, nonce))
    enc_chunk = _AGE_STREAM_CHUNK + 16
    out = bytearray()
    n = (len(body) + enc_chunk - 1) // enc_chunk or 1
    for i in range(n):
        piece = body[i * enc_chunk:(i + 1) * enc_chunk]
        last = i == n - 1
        cnonce = i.to_bytes(11, "big") + (b"\x01" if last else b"\x00")
        try:
            out += aead.decrypt(cnonce, piece, None)
        except Exception:
            raise ToolError("The age file did not decrypt - wrong key, or it has been "
                            "altered.")
    return bytes(out)


def _age_header_mac(file_key, header_no_mac):
    import hmac as _hmac
    import hashlib
    mac_key = _hkdf(file_key, b"", b"header")
    return _hmac.new(mac_key, header_no_mac, hashlib.sha256).digest()


def _age_encrypt(data, recipient="", passphrase="", armour=True, **_k):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    recipient, passphrase = recipient.strip(), passphrase.strip()
    if not recipient and not passphrase:
        raise ToolError("Give a recipient (an age1... public key) to encrypt to, or a "
                        "passphrase.")
    if recipient and passphrase:
        raise ToolError("Use a recipient or a passphrase, not both.")
    plaintext = to_bytes(data)
    file_key = os.urandom(16)

    lines = ["age-encryption.org/v1"]
    if recipient:
        r_raw = _age_recipient_raw(recipient)
        eph = _x25519().X25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization
        eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw)
        shared = eph.exchange(_x25519().X25519PublicKey.from_public_bytes(r_raw))
        wrap = _hkdf(shared, eph_pub + r_raw, b"age-encryption.org/v1/X25519")
        wrapped = ChaCha20Poly1305(wrap).encrypt(b"\x00" * 12, file_key, None)
        lines.append("-> X25519 " + _b64(eph_pub))
        lines.append(_b64(wrapped))
    else:
        salt = os.urandom(16)
        work = 18
        import hashlib
        wrap = hashlib.scrypt(passphrase.encode(),
                              salt=b"age-encryption.org/v1/scrypt" + salt,
                              n=1 << work, r=8, p=1, dklen=32, maxmem=(1 << work) * 8 * 128 * 2)
        wrapped = ChaCha20Poly1305(wrap).encrypt(b"\x00" * 12, file_key, None)
        lines.append("-> scrypt " + _b64(salt) + " " + str(work))
        lines.append(_b64(wrapped))

    header_no_mac = ("\n".join(lines) + "\n---").encode()
    mac = _age_header_mac(file_key, header_no_mac)
    header = header_no_mac + b" " + _b64(mac).encode() + b"\n"
    payload = _age_encrypt_payload(file_key, plaintext)
    blob = header + payload

    if armour:
        b = base64.b64encode(blob).decode()
        wrapped_txt = "\n".join(b[i:i + 64] for i in range(0, len(b), 64))
        text = "-----BEGIN AGE ENCRYPTED FILE-----\n" + wrapped_txt + \
               "\n-----END AGE ENCRYPTED FILE-----\n"
        return Result(text=text, data=blob, suggested_name="message.age",
                      note="Encrypted with age. Anyone with the matching identity - and no "
                           "one else - can read it.")
    return Result(data=blob, suggested_name="message.age",
                  text="(binary age file - use Save)",
                  note="Encrypted with age.")


def _age_decrypt(data, identity="", passphrase="", **_k):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    raw = to_bytes(data)
    text = to_text(data)
    if "BEGIN AGE ENCRYPTED FILE" in text:
        inner = text.split("-----")[2]
        raw = base64.b64decode("".join(inner.split()))
    elif not raw.startswith(b"age-encryption.org"):
        try:
            raw = base64.b64decode("".join(text.split()))
        except Exception:
            pass
    if not raw.startswith(b"age-encryption.org"):
        raise ToolError("This is not an age file (the age-encryption.org header is missing).")

    nl = raw.index(b"\n---")
    header_body = raw[:nl]
    rest = raw[nl + 4:]
    mac_end = rest.index(b"\n")
    mac_b64 = rest[:mac_end].strip()
    payload = rest[mac_end + 1:]
    stanzas = header_body.decode().split("\n")[1:]

    identity, passphrase = identity.strip(), passphrase.strip()
    file_key = None
    i = 0
    while i < len(stanzas):
        line = stanzas[i]
        if line.startswith("-> X25519 ") and identity:
            eph_pub = _unb64(line[len("-> X25519 "):])
            wrapped = _unb64(stanzas[i + 1])
            try:
                priv = _age_pub_from_secret(identity)
                from cryptography.hazmat.primitives import serialization
                my_pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                                        serialization.PublicFormat.Raw)
                shared = priv.exchange(_x25519().X25519PublicKey.from_public_bytes(eph_pub))
                wrap = _hkdf(shared, eph_pub + my_pub, b"age-encryption.org/v1/X25519")
                file_key = ChaCha20Poly1305(wrap).decrypt(b"\x00" * 12, wrapped, None)
                break
            except ToolError:
                raise
            except Exception:
                pass
        elif line.startswith("-> scrypt ") and passphrase:
            parts = line.split()
            salt_b64, work = parts[2], parts[3]
            wrapped = _unb64(stanzas[i + 1])
            import hashlib
            salt = _unb64(salt_b64)
            wrap = hashlib.scrypt(passphrase.encode(),
                                  salt=b"age-encryption.org/v1/scrypt" + salt,
                                  n=1 << int(work), r=8, p=1, dklen=32,
                                  maxmem=(1 << int(work)) * 8 * 128 * 2)
            try:
                file_key = ChaCha20Poly1305(wrap).decrypt(b"\x00" * 12, wrapped, None)
                break
            except Exception:
                raise ToolError("Wrong passphrase for this age file.")
        i += 2 if line.startswith("-> ") else 1

    if file_key is None:
        has_x = any(s.startswith("-> X25519") for s in stanzas)
        has_scrypt = any(s.startswith("-> scrypt") for s in stanzas)
        if has_scrypt and not passphrase:
            raise ToolError("This age file is passphrase-encrypted - type the passphrase.")
        if has_x and not identity:
            raise ToolError("This age file is encrypted to a key - paste your secret "
                            "identity (AGE-SECRET-KEY-...).")
        raise ToolError("None of your keys open this file. It was encrypted to a "
                        "different recipient.")

    import hmac as _hmac
    want = _age_header_mac(file_key, header_body + b"\n---")
    if not _hmac.compare_digest(want, _unb64(mac_b64.decode())):
        raise ToolError("The age header failed its integrity check - the file is corrupt "
                        "or tampered with.")
    out = _age_decrypt_payload(file_key, payload)
    try:
        return Result(text=out.decode("utf-8"),
                      note="Decrypted.", prefer="text")
    except UnicodeDecodeError:
        return Result(data=out, text="(binary - use Save)", suggested_name="decrypted.bin",
                      note="Decrypted.")


tool(id="age-keygen", name="age key pair", category=CAT,
     summary="Make an age identity - a public 'age1...' and its secret key",
     explain=(
         "age keys are the whole reason age is pleasant to use: no key servers, no web of "
         "trust, no options. A recipient key is one short line starting 'age1' that you can "
         "paste into a chat or put on a business card. The matching secret starts "
         "'AGE-SECRET-KEY-' and never leaves your machine.\n\n"
         "Hand the recipient key to anyone who wants to send you something. Keep the secret. "
         "Lose the secret and what was sent to you is gone - there is no recovery, by "
         "design."),
     tags=["age", "keygen", "identity", "x25519", "recipient"],
     input_kind="none", action=_age_keygen, action_label="Generate")


tool(id="age", name="age encryption", category=CAT,
     summary="Encrypt and decrypt files the way the age tool does",
     explain=(
         "age is what most people reach for now when PGP would once have been the answer: "
         "encrypt a file so that one specific person - or anyone holding a passphrase - can "
         "open it, and nobody else. It is deliberately small. There is one modern cipher "
         "(ChaCha20-Poly1305), one key type (X25519), and no knobs to get wrong.\n\n"
         "Encrypt to a recipient's age1 key and only their secret opens it. Or set a "
         "passphrase and anyone with the passphrase can open it - handy for a file you are "
         "sending to yourself. The armoured output is safe to paste into an email; untick it "
         "for a smaller binary .age file.\n\n"
         "What comes out is a real age file: the age command-line tool, and every app built "
         "on it, will open it, and will open theirs here."),
     example="Make a key pair with 'age key pair', then encrypt to its age1... recipient.",
     tags=["age", "encrypt", "decrypt", "x25519", "chacha20", "file", "interop"],
     params=[Param("recipient", "Recipient (age1...)", "text", "", width=34, only="encode",
                   help="The public key of whoever should be able to read it."),
             Param("passphrase", "Or a passphrase", "password", "", width=22,
                   help="Encrypt with a passphrase instead of a key. Both ends need it."),
             Param("identity", "Your secret identity", "text", "", width=34, only="decode",
                   help="AGE-SECRET-KEY-... - needed unless the file used a passphrase."),
             Param("armour", "Armoured text output", "bool", True, only="encode",
                   help="On: paste-safe text. Off: a smaller binary file.")],
     encode=_age_encrypt, decode=_age_decrypt,
     encode_label="Encrypt", decode_label="Decrypt", binary_ok=True)


# --------------------------------------------------------------------------
# Key and certificate format conversion
# --------------------------------------------------------------------------

def _sniff_and_load(blob: bytes):
    """Return (kind, object) for whatever key or certificate this is."""
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    text = blob.lstrip()
    # PEM
    if text[:1] == b"-":
        for label, loader in (
            ("private", lambda b: serialization.load_pem_private_key(b, None)),
            ("public", serialization.load_pem_public_key),
            ("cert", x509.load_pem_x509_certificate),
            ("csr", x509.load_pem_x509_csr)):
            try:
                return label, loader(text)
            except Exception:
                continue
        # OpenSSH public
        try:
            return "public", serialization.load_ssh_public_key(text)
        except Exception:
            pass
        raise ToolError("That is a PEM block, but not a key, certificate or CSR Cryptex "
                        "can read - or it needs a passphrase this tool was not given.")
    # DER
    for label, loader in (
        ("private", lambda b: serialization.load_der_private_key(b, None)),
        ("public", serialization.load_der_public_key),
        ("cert", x509.load_der_x509_certificate),
        ("csr", x509.load_der_x509_csr)):
        try:
            return label, loader(blob)
        except Exception:
            continue
    raise ToolError("Could not recognise that as a key or certificate in PEM or DER form.")


def _convert_key(data, target="PEM (standard)", **_k):
    from cryptography.hazmat.primitives import serialization
    blob = to_bytes(data)
    kind, obj = _sniff_and_load(blob)
    enc_pem = serialization.Encoding.PEM
    enc_der = serialization.Encoding.DER

    def private_out(fmt, enc):
        return obj.private_bytes(enc, fmt, serialization.NoEncryption())

    rows = [("Recognised as", {"private": "a private key", "public": "a public key",
                               "cert": "a certificate", "csr": "a certificate request"}[kind])]

    if target == "public key only":
        if kind == "private":
            pub = obj.public_key()
        elif kind in ("cert", "csr"):
            pub = obj.public_key()
        else:
            pub = obj
        out = pub.public_bytes(enc_pem, serialization.PublicFormat.SubjectPublicKeyInfo)
        name = "public.pem"
    elif target == "OpenSSH public":
        pub = obj.public_key() if kind in ("private", "cert", "csr") else obj
        out = pub.public_bytes(enc_pem if False else serialization.Encoding.OpenSSH,
                               serialization.PublicFormat.OpenSSH) + b"\n"
        name = "id.pub"
    elif target == "DER (binary)":
        if kind == "private":
            out = private_out(serialization.PrivateFormat.PKCS8, enc_der)
        elif kind == "public":
            out = obj.public_bytes(enc_der, serialization.PublicFormat.SubjectPublicKeyInfo)
        elif kind == "cert":
            out = obj.public_bytes(enc_der)
        else:
            out = obj.public_bytes(enc_der)
        name = {"private": "key.der", "public": "public.der",
                "cert": "cert.der", "csr": "request.der"}[kind]
        return Result(data=out, suggested_name=name, rows=rows, headers=["", ""],
                      text=f"(binary DER, {len(out)} bytes - use Save)",
                      note="Converted to DER. Windows and Java tools often want this rather "
                           "than PEM.")
    else:  # PEM (standard)
        if kind == "private":
            out = private_out(serialization.PrivateFormat.PKCS8, enc_pem)
        elif kind == "public":
            out = obj.public_bytes(enc_pem, serialization.PublicFormat.SubjectPublicKeyInfo)
        elif kind == "cert":
            out = obj.public_bytes(enc_pem)
        else:
            out = obj.public_bytes(enc_pem)
        name = {"private": "key.pem", "public": "public.pem",
                "cert": "cert.pem", "csr": "request.pem"}[kind]

    text = out.decode("utf-8", "replace")
    return Result(text=text, data=out, suggested_name=name, rows=rows, headers=["", ""],
                  prefer="text", note="Converted.")


tool(id="convert-key", name="Convert a key or certificate", category=CAT,
     summary="PEM to DER, pull out the public half, or write an OpenSSH key",
     explain=(
         "The same key turns up wanting to be in three or four different wrappers depending "
         "on what is reading it. This moves between them without touching the key itself.\n\n"
         "Paste any private key, public key, certificate or CSR - PEM (the '-----BEGIN' text) "
         "or DER (binary) - and it works out what it is. Then:\n\n"
         "- PEM to DER and back: DER is the raw binary form Windows and Java keystores usually "
         "expect; PEM is the base64 text everything else uses.\n"
         "- Public key only: strips a private key or certificate down to just the public half, "
         "safe to hand out.\n"
         "- OpenSSH public: the 'ssh-ed25519 AAAA...' one line that goes in authorized_keys.\n\n"
         "It never changes the key material, so a round trip gives back exactly what you "
         "started with."),
     tags=["pem", "der", "convert", "key", "certificate", "openssh", "pkcs8", "public"],
     params=[Param("target", "Convert to", "choice", "PEM (standard)",
                   choices=["PEM (standard)", "DER (binary)", "public key only",
                            "OpenSSH public"])],
     action=_convert_key, action_label="Convert", binary_ok=True, input_kind="text")


def _pkcs12_build(data, cert="", password="", name="cryptex", **_k):
    """data is the private key (PEM); cert is the matching certificate (PEM)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography import x509
    key_blob, cert_blob = to_bytes(data), to_bytes(cert)
    need(key_blob, "Paste the private key (PEM) in the main box.")
    need(cert_blob, "Paste the matching certificate (PEM) in the certificate box.")
    try:
        key = serialization.load_pem_private_key(key_blob, None)
    except Exception as exc:
        raise ToolError(f"Could not read the private key: {exc}")
    try:
        certificate = x509.load_pem_x509_certificate(cert_blob)
    except Exception as exc:
        raise ToolError(f"Could not read the certificate: {exc}")
    enc = (serialization.BestAvailableEncryption(password.encode())
           if password else serialization.NoEncryption())
    blob = pkcs12.serialize_key_and_certificates(
        name.encode() or b"cryptex", key, certificate, None, enc)
    return Result(data=blob, suggested_name=(name or "bundle") + ".pfx",
                  rows=[("Bundle", (name or "cryptex")),
                        ("Contains", "1 private key + 1 certificate"),
                        ("Protected", "yes, with a password" if password else "NO password")],
                  headers=["", ""], text=f"(binary .pfx, {len(blob)} bytes - use Save)",
                  note="A PKCS#12 bundle. Import it into Windows, macOS Keychain or a browser.",
                  warn=None if password else
                       "No password set - the private key inside is unprotected. Set one "
                       "unless this never leaves your machine.")


def _pkcs12_open(data, password="", **_k):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    blob = to_bytes(data)
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(
            blob, password.encode() if password else None)
    except Exception:
        raise ToolError("Could not open that .pfx/.p12 - wrong password, or not a PKCS#12 "
                        "file.")
    parts, rows = [], []
    if key is not None:
        pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
        parts.append(pem)
        rows.append(("Private key", "extracted (now unencrypted - handle with care)"))
    if cert is not None:
        parts.append(cert.public_bytes(serialization.Encoding.PEM).decode())
        rows.append(("Certificate", cert.subject.rfc4514_string()))
    for c in (extra or []):
        parts.append(c.public_bytes(serialization.Encoding.PEM).decode())
    if extra:
        rows.append(("Chain certificates", str(len(extra))))
    return Result(text="\n".join(parts), rows=rows, headers=["", ""], prefer="text",
                  note="Unpacked the bundle into PEM. The private key is no longer "
                       "password-protected in this output.")


tool(id="pkcs12", name="PKCS#12 (.pfx / .p12) bundle", category=CAT,
     summary="Package a key and certificate into a .pfx, or open one",
     explain=(
         "A .pfx (also .p12) is one password-protected file holding a private key and its "
         "certificate together. It is how Windows, macOS Keychain, browsers and a lot of "
         "enterprise kit expect to be handed an identity - IIS, code-signing certs, client "
         "certificates all arrive this way.\n\n"
         "To build one: paste the private key (PEM) in the main box, the matching certificate "
         "(PEM) in the certificate box, set a password, and Encode. To open one: switch to "
         "Decode, load the .pfx and give its password, and it hands back the key and "
         "certificate as PEM.\n\n"
         "Opening a bundle strips the password from the key in the output, so only do it "
         "somewhere you trust."),
     tags=["pkcs12", "pfx", "p12", "bundle", "certificate", "windows", "keychain", "import"],
     params=[Param("cert", "Certificate (PEM)", "multiline", "", width=40, only="encode",
                   help="The certificate that matches the private key in the main box."),
             Param("password", "Password", "password", "", width=22,
                   help="Protects the bundle. Needed to open it again."),
             Param("name", "Friendly name", "text", "cryptex", width=16, only="encode")],
     encode=_pkcs12_build, decode=_pkcs12_open,
     encode_label="Build .pfx", decode_label="Open .pfx", binary_ok=True)


# --------------------------------------------------------------------------
# QR codes
# --------------------------------------------------------------------------

def _qr_make(data, error="M", scale=8, border=4, outdir="", **_k):
    try:
        import segno
    except ImportError:
        raise ToolError("Making QR codes needs the 'segno' library. The build bundles it - "
                        "if you are running from source, install it with:  pip install segno")
    text = to_text(data)
    if not text.strip():
        raise ToolError("Type something to turn into a QR code.")
    error = (error or "M").upper()[0].lower()
    if error not in ("l", "m", "q", "h"):
        error = "m"
    try:
        # make_qr, never make: make() picks the smallest symbol, which for short
        # data is a Micro QR - and phone cameras (iPhone included) cannot read
        # Micro QR at all. A full QR is what scanners expect.
        qr = segno.make_qr(text, error=error)
    except Exception as exc:
        raise ToolError(f"Could not encode that as a QR code: {exc}. If the text is very "
                        "long, a QR code cannot hold it - shorten it or split it up.")
    folder = outdir or "."
    dest = os.path.join(folder, "qr.png")
    i = 2
    while os.path.exists(dest):
        dest = os.path.join(folder, f"qr-{i}.png")
        i += 1
    # a quiet zone of at least 4 modules and a solid white background are what
    # make it reliably scannable; do not let the border drop below 4
    qr.save(dest, scale=int(clamp(scale, 1, 40, 8)),
            border=max(4, int(clamp(border, 0, 16, 4))),
            dark="black", light="white")
    version = getattr(qr, "version", "?")
    return Result(file_path=dest, image_path=dest,
                  rows=[("Characters", len(text)),
                        ("QR version", version),
                        ("Error correction", {"l": "L (7%)", "m": "M (15%)",
                                              "q": "Q (25%)", "h": "H (30%)"}[error]),
                        ("Saved to", dest)],
                  headers=["", ""],
                  note=f"QR code written to {dest}. Point a phone camera at it.")


def _qr_read(data, **_k):
    path = need(data, "Pick a QR code image to read.")
    if not isinstance(path, str) or not os.path.isfile(path):
        raise ToolError("Pick an image file containing a QR code.")
    try:
        from pyzbar.pyzbar import decode as zbar_decode
        from PIL import Image
    except ImportError:
        raise ToolError("Reading a QR code from an image is not bundled (it needs the zbar "
                        "system library). Generating them works; to read one, a phone camera "
                        "is the easy route.")
    results = zbar_decode(Image.open(path))
    if not results:
        raise ToolError("No QR code found in that image.")
    texts = [r.data.decode("utf-8", "replace") for r in results]
    return Result(text="\n".join(texts),
                  rows=[("Codes found", len(texts))], headers=["", ""], prefer="text",
                  note=f"Read {len(texts)} code(s).")


tool(id="qr", name="QR code", category=CAT,
     summary="Turn text into a QR code image (and read one back where possible)",
     explain=(
         "A QR code is the easiest way to move a short piece of text off a screen and onto a "
         "phone without typing it - a key, a two-factor secret, a wallet address, a Wi-Fi "
         "password, a link.\n\n"
         "Encode writes a PNG. The error-correction level controls how much of the code can "
         "be dirty or obscured and still scan: L survives about 7% damage, H about 30%. "
         "Higher levels make the code denser. M is the usual choice.\n\n"
         "Reading a code back out of an image works if your machine has the zbar library; if "
         "not, a phone camera is the simple route, and Cryptex will tell you rather than fail "
         "quietly."),
     example="Paste an age recipient key or a TOTP secret and scan the result with a phone.",
     tags=["qr", "qrcode", "barcode", "encode", "phone", "2fa", "wifi"],
     params=[Param("error", "Error correction", "choice", "M", only="encode",
                   choices=["L", "M", "Q", "H"],
                   help="How much damage the code can take and still scan. Higher = denser."),
             Param("scale", "Pixel size", "int", 8, minimum=1, maximum=40, only="encode"),
             Param("border", "Quiet border", "int", 4, minimum=4, maximum=16, only="encode",
                   help="Blank margin in modules. 4 is the minimum a scanner expects."),
             Param("outdir", "Save into", "folder", "", only="encode")],
     encode=_qr_make, decode=_qr_read,
     encode_label="Make QR", decode_label="Read QR (needs an image)",
     input_kind="text")

