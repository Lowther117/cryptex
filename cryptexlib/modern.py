"""Modern encryption — the part of the app you would actually trust.

Everything here is authenticated encryption: if one bit of the ciphertext is
changed, decryption fails loudly rather than returning wrong plaintext.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import string
import struct
import time

from .core import (Param, Result, ToolError, b64_any, need, pretty_hex,
                   to_bytes, to_text, tool)

CAT = "Encryption"

MAGIC = b"CRYPTEX1"          # file header so a Cryptex file is recognisable
KDF_CHOICES = ["Argon2id (best, if installed)", "scrypt", "PBKDF2-SHA256"]

EXPLAIN_AEAD = (
    "AES-256-GCM is the encryption behind HTTPS, disk encryption and most modern file "
    "formats. It does two jobs at once: it hides the contents, and it adds a tag that proves "
    "nothing has been altered. Change a single byte of the ciphertext and decryption refuses "
    "rather than quietly giving you the wrong answer.\n\n"
    "Your password never becomes the key directly. It is stretched by a key derivation "
    "function — Argon2id, scrypt or PBKDF2 — with a random salt, so guessing passwords is "
    "slow and two files encrypted with the same password still get different keys.\n\n"
    "A fresh random nonce is used every time. Reusing a nonce with the same key is the one "
    "thing that breaks GCM completely, so Cryptex never lets you choose it.")

SEC_NOTE = ("Strength comes entirely from the password. A long passphrase of several unrelated "
            "words beats a short complicated one. There is no recovery — lose the password and "
            "the data is gone.")


def _derive(password: str, salt: bytes, kdf: str, work: int) -> tuple[bytes, dict]:
    from .core import clamp
    work = clamp(work, 1000, 20_000_000, 200_000)
    import hashlib
    if kdf.startswith("Argon2"):
        try:
            from argon2.low_level import Type, hash_secret_raw
        except ImportError:
            kdf = "scrypt"
        else:
            t, m = max(1, work // 100000), 65536
            key = hash_secret_raw(password.encode(), salt, time_cost=max(2, t),
                                  memory_cost=m, parallelism=2, hash_len=32, type=Type.ID)
            return key, {"kdf": "argon2id", "t": max(2, t), "m": m, "p": 2}
    if kdf == "scrypt":
        n = 1 << min(17, max(14, work.bit_length() - 1))
        key = hashlib.scrypt(password.encode(), salt=salt, n=n, r=8, p=1, dklen=32,
                             maxmem=n * 8 * 128 * 3)
        return key, {"kdf": "scrypt", "n": n, "r": 8, "p": 1}
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, work, 32)
    return key, {"kdf": "pbkdf2-sha256", "iter": work}


def _rederive(password: str, salt: bytes, meta: dict) -> bytes:
    import hashlib
    k = meta.get("kdf")
    if k == "argon2id":
        from argon2.low_level import Type, hash_secret_raw
        return hash_secret_raw(password.encode(), salt, time_cost=meta["t"],
                               memory_cost=meta["m"], parallelism=meta["p"],
                               hash_len=32, type=Type.ID)
    if k == "scrypt":
        return hashlib.scrypt(password.encode(), salt=salt, n=meta["n"], r=meta["r"],
                              p=meta["p"], dklen=32, maxmem=meta["n"] * 8 * 128 * 3)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, meta["iter"], 32)


def _aead(key: bytes, cipher: str):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    return ChaCha20Poly1305(key) if cipher.startswith("ChaCha") else AESGCM(key)


# --------------------------------------------------------------------------
# Text
# --------------------------------------------------------------------------

tool(id="aes-text", name="Encrypt text with a password", category=CAT,
     summary="AES-256-GCM or ChaCha20-Poly1305, password-derived key",
     explain=EXPLAIN_AEAD, security=SEC_NOTE,
     tags=["aes", "gcm", "chacha20", "password", "aead", "authenticated"],
     params=[Param("password", "Password", "password", ""),
             Param("cipher", "Cipher", "choice", "AES-256-GCM",
                   choices=["AES-256-GCM", "ChaCha20-Poly1305"]),
             Param("kdf", "Key derivation", "choice", "scrypt", choices=KDF_CHOICES, only="encode"),
             Param("work", "Work factor", "int", 200000, only="encode",
                   help="Higher is slower to attack and slower for you. 200,000 is a sensible floor."),
             Param("armour", "Output as", "choice", "Base64", choices=["Base64", "Hex"], only="encode"),
             Param("aad", "Extra data to authenticate (optional)", "text", "", width=20,
                   help="Not encrypted, but decryption fails unless it matches. Good for a filename or an ID.")],
     encode=lambda d, password="", cipher="AES-256-GCM", kdf="scrypt", work=200000,
                   armour="Base64", aad="": _enc_text(d, password, cipher, kdf, int(work), armour, aad),
     decode=lambda d, password="", cipher="AES-256-GCM", aad="", **k:
         _dec_text(d, password, aad),
     encode_label="Encrypt", decode_label="Decrypt", binary_ok=True)


def _pack(meta: dict, salt: bytes, nonce: bytes, ct: bytes) -> bytes:
    head = json.dumps(meta, separators=(",", ":")).encode()
    return MAGIC + struct.pack("<H", len(head)) + head + \
        bytes([len(salt)]) + salt + bytes([len(nonce)]) + nonce + ct


def _unpack(raw: bytes):
    if not raw.startswith(MAGIC):
        raise ToolError("This does not look like something Cryptex encrypted "
                        "(the CRYPTEX1 header is missing). Check you pasted the whole thing.")
    p = len(MAGIC)
    hlen = struct.unpack_from("<H", raw, p)[0]
    p += 2
    meta = json.loads(raw[p:p + hlen])
    p += hlen
    slen = raw[p]; p += 1
    salt = raw[p:p + slen]; p += slen
    nlen = raw[p]; p += 1
    nonce = raw[p:p + nlen]; p += nlen
    return meta, salt, nonce, raw[p:]


def _enc_text(data, password, cipher, kdf, work, armour, aad):
    need(password, "Type a password — the encryption is only as good as it is.")
    salt, nonce = os.urandom(16), os.urandom(12)
    key, meta = _derive(password, salt, kdf, work)
    meta["cipher"] = "chacha20poly1305" if cipher.startswith("ChaCha") else "aes-256-gcm"
    meta["v"] = 1
    ct = _aead(key, cipher).encrypt(nonce, to_bytes(data), aad.encode() if aad else None)
    blob = _pack(meta, salt, nonce, ct)
    out = blob.hex() if armour == "Hex" else base64.b64encode(blob).decode()
    return Result(text="\n".join(out[i:i + 76] for i in range(0, len(out), 76)),
                  data=blob, suggested_name="message.cryptex",
                  note=f"{meta['cipher'].upper()} with {meta['kdf']}. "
                       "Everything needed to decrypt except the password is inside this block.")


def _dec_text(data, password, aad):
    need(password, "Type the password used to encrypt it.")
    raw = to_bytes(data)
    if not raw.startswith(MAGIC):
        txt = to_text(data).strip()
        try:
            raw = bytes.fromhex("".join(txt.split())) if all(
                c in string.hexdigits or c.isspace() for c in txt) else b64_any(txt)
        except Exception:
            raw = b64_any(txt)
    meta, salt, nonce, ct = _unpack(raw)
    key = _rederive(password, salt, meta)
    cipher = "ChaCha20" if meta.get("cipher", "").startswith("chacha") else "AES"
    try:
        pt = _aead(key, cipher).decrypt(nonce, ct, aad.encode() if aad else None)
    except Exception:
        raise ToolError("Decryption failed. Either the password is wrong, the extra "
                        "authenticated data does not match, or the ciphertext has been "
                        "altered. Authenticated encryption cannot tell you which.") from None
    try:
        return Result(text=pt.decode("utf-8"), data=pt,
                      note=f"Decrypted and verified intact ({meta.get('cipher')}, {meta.get('kdf')}).")
    except UnicodeDecodeError:
        return Result(text=pretty_hex(pt), data=pt,
                      note="Decrypted and verified — the content is binary, use Save.")


# --------------------------------------------------------------------------
# Files and folders
# --------------------------------------------------------------------------

tool(id="aes-file", name="Encrypt a file", category=CAT,
     summary="Password-encrypt any file to a .cryptex, and back again",
     explain=(EXPLAIN_AEAD + "\n\nFiles are processed in 1 MB chunks, each separately "
              "authenticated and numbered, so a very large file never has to fit in memory "
              "and nobody can reorder or drop a chunk without decryption failing.\n\n"
              "The original file name is stored inside the encrypted file, so decrypting "
              "restores it even if the .cryptex was renamed."),
     security=SEC_NOTE + " Cryptex never deletes your original — do that yourself once you have "
                         "checked the encrypted copy opens.",
     tags=["file", "aes", "gcm", "chunked", "large"],
     input_kind="file", input_label="File",
     params=[Param("password", "Password", "password", ""),
             Param("cipher", "Cipher", "choice", "AES-256-GCM",
                   choices=["AES-256-GCM", "ChaCha20-Poly1305"], only="encode"),
             Param("kdf", "Key derivation", "choice", "scrypt", choices=KDF_CHOICES, only="encode"),
             Param("work", "Work factor", "int", 200000, only="encode"),
             Param("outdir", "Save to folder (blank = beside the original)", "folder", "")],
     encode=lambda path, password="", cipher="AES-256-GCM", kdf="scrypt", work=200000, outdir="":
         _enc_file(path, password, cipher, kdf, int(work), outdir),
     decode=lambda path, password="", outdir="", **k: _dec_file(path, password, outdir),
     encode_label="Encrypt file", decode_label="Decrypt file")

CHUNK = 1 << 20


def _enc_file(path, password, cipher, kdf, work, outdir):
    path = need(path, "Pick a file to encrypt.")
    need(password, "Type a password.")
    if not os.path.isfile(path):
        raise ToolError(f"Not a file: {path}")
    salt = os.urandom(16)
    key, meta = _derive(password, salt, kdf, work)
    meta.update(cipher="chacha20poly1305" if cipher.startswith("ChaCha") else "aes-256-gcm",
                v=1, name=os.path.basename(path), size=os.path.getsize(path),
                chunk=CHUNK, when=int(time.time()))
    aead = _aead(key, cipher)
    base = os.urandom(8)
    out_dir = outdir or os.path.dirname(os.path.abspath(path))
    out = os.path.join(out_dir, os.path.basename(path) + ".cryptex")
    head = json.dumps(meta, separators=(",", ":")).encode()
    with open(path, "rb") as src, open(out, "wb") as dst:
        dst.write(MAGIC + struct.pack("<H", len(head)) + head +
                  bytes([len(salt)]) + salt + bytes([len(base)]) + base)
        i = 0
        while True:
            chunk = src.read(CHUNK)
            last = len(chunk) < CHUNK
            nonce = base + struct.pack("<I", i)
            ct = aead.encrypt(nonce, chunk, b"L" if last else b"C")
            dst.write(struct.pack("<I", len(ct)) + ct)
            i += 1
            if last:
                break
    return Result(file_path=out,
                  rows=[("Original", path), ("Encrypted", out),
                        ("Cipher", meta["cipher"]), ("Key derivation", meta["kdf"]),
                        ("Chunks", i)],
                  headers=["", ""],
                  note=f"Written to {out}. The original is untouched — delete it yourself "
                       "once you have confirmed this file decrypts.")


def _dec_file(path, password, outdir):
    path = need(path, "Pick a .cryptex file to decrypt.")
    need(password, "Type the password.")
    if not os.path.isfile(path):
        raise ToolError(f"Not a file: {path}")
    try:
        src = open(path, "rb")
    except OSError as exc:
        raise ToolError(f"Could not open that file ({exc}).") from exc
    with src:
        if src.read(len(MAGIC)) != MAGIC:
            raise ToolError("That is not a Cryptex-encrypted file. Encrypted files "
                            "start with a CRYPTEX1 header and normally end in "
                            ".cryptex.")
        hlen = struct.unpack("<H", src.read(2))[0]
        meta = json.loads(src.read(hlen))
        salt = src.read(src.read(1)[0])
        base = src.read(src.read(1)[0])
        key = _rederive(password, salt, meta)
        cipher = "ChaCha20" if meta.get("cipher", "").startswith("chacha") else "AES"
        aead = _aead(key, cipher)
        out_dir = outdir or os.path.dirname(os.path.abspath(path))
        # the header is not authenticated, so the name in it is only ever a
        # name - never a path that could climb out of the chosen folder
        name = (os.path.basename(str(meta.get("name") or "").replace("\\", "/"))
                or os.path.basename(path).replace(".cryptex", ""))
        out = os.path.join(out_dir, name)
        n = 1
        while os.path.exists(out):
            stem, ext = os.path.splitext(name)
            out = os.path.join(out_dir, f"{stem} ({n}){ext}")
            n += 1
        i = 0
        failed, last_tag = False, None
        with open(out, "wb") as dst:
            while True:
                head = src.read(4)
                if not head:
                    break
                clen = struct.unpack("<I", head)[0] if len(head) == 4 else 0
                ct = src.read(clen)
                nonce = base + struct.pack("<I", i)
                for tag in (b"C", b"L"):
                    try:
                        dst.write(aead.decrypt(nonce, ct, tag))
                        last_tag = tag
                        break
                    except Exception:
                        continue
                else:
                    failed = True
                    break
                i += 1
        # Only the final chunk is sealed as "L", so a file cut off at a chunk
        # boundary shows up here. The output is removed after it is closed -
        # Windows will not delete a file that is still open.
        if failed or last_tag != b"L":
            os.unlink(out)
            raise ToolError("Decryption failed at chunk %d — wrong password, or the "
                            "file has been altered or truncated." % i) from None
    return Result(file_path=out,
                  rows=[("Encrypted", path), ("Restored to", out),
                        ("Original name", meta.get("name", "?")),
                        ("Encrypted on", time.strftime("%d %b %Y %H:%M",
                                                       time.localtime(meta.get("when", 0)))
                         if meta.get("when") else "unknown")],
                  headers=["", ""],
                  note=f"Decrypted and verified intact. Written to {out}.")


tool(id="aes-folder", name="Encrypt a folder", category=CAT,
     summary="Zip a whole folder, then encrypt the zip",
     explain=("Folders are handled the honest way: everything is packed into a single zip "
              "first, then that zip is encrypted as one file. That means the file names inside "
              "are hidden too, which per-file encryption would not do.\n\n"
              "Decrypting gives you the zip back; unzip it wherever you want it."),
     security=SEC_NOTE,
     tags=["folder", "directory", "zip", "archive", "backup"],
     input_kind="folder", input_label="Folder",
     params=[Param("password", "Password", "password", ""),
             Param("kdf", "Key derivation", "choice", "scrypt", choices=KDF_CHOICES),
             Param("work", "Work factor", "int", 200000),
             Param("outdir", "Save to folder (blank = beside the original)", "folder", "")],
     action=lambda path, password="", kdf="scrypt", work=200000, outdir="":
         _enc_folder(path, password, kdf, int(work), outdir),
     action_label="Zip and encrypt")


def _enc_folder(path, password, kdf, work, outdir):
    import shutil
    import tempfile
    path = need(path, "Pick a folder.")
    need(password, "Type a password.")
    if not os.path.isdir(path):
        raise ToolError(f"Not a folder: {path}")
    tmp = tempfile.mkdtemp(prefix="cryptex-")
    try:
        zpath = shutil.make_archive(os.path.join(tmp, os.path.basename(os.path.abspath(path))),
                                    "zip", path)
        res = _enc_file(zpath, password, "AES-256-GCM", kdf, work,
                        outdir or os.path.dirname(os.path.abspath(path)))
        nfiles = sum(len(f) for _, _, f in os.walk(path))
        res.note = (f"{nfiles} file(s) zipped and encrypted to {res.file_path}. "
                    "Decrypt it with 'Encrypt a file' to get the zip back.")
        return res
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# Generators
# --------------------------------------------------------------------------

WORDS = ("able about above acid across act add afraid after again against age agree air all "
         "allow also always among amount anger angle animal answer any apple apply arch area "
         "argue arm army arrive art ask attack attempt author autumn awake away baby back bad "
         "bag bake balance ball band bank bar base basket bath beam bean bear beat beauty bed "
         "before begin behind belief bell belt bend berry best better between beyond bird birth "
         "bite bitter black blade blame blank blast blind block blood blow blue board boat body "
         "boil bold bone book boot border born borrow both bottle bottom bowl box boy brain "
         "branch brass brave bread break breath brick bridge bright bring broad broken brother "
         "brown brush bucket build bulb bunch burn burst bush business busy butter button cake "
         "call calm camp canal cancel candle cap card care carry cart case cast cat catch cause "
         "cave cell centre certain chain chalk chance change charge chase cheap check cheese "
         "chest chief child choose church circle city claim clay clean clear clerk clever cliff "
         "climb clock close cloth cloud coal coast coat code coffee coin cold collar colour comb "
         "come common cook cool copper copy cord cork corn corner correct cost cotton cough "
         "count country course cover cow crack crash cream crime cross crowd crown cruel crush "
         "cry cup curl current curtain curve cushion cut cycle damage damp dance danger dare "
         "dark date daughter dawn day dead deal dear debate decide deep deer degree delay "
         "deliver demand dense depend depth desert design desk detail develop device diamond "
         "differ dig dinner direct dirty disk distance ditch dive divide dog door double doubt "
         "down dozen drag drain draw dream dress drift drill drink drive drop drum dry duck dust "
         "duty eager eagle early earn earth east easy edge effort egg eight either elbow elder "
         "electric else empty end enemy engine enjoy enough enter equal escape even event ever "
         "every exact example exchange exist expect expert explain extra eye face fact fade fail "
         "faint fair faith fall false family famous fancy far farm fast fat fault favour fear "
         "feather feed feel fence fever few field fierce fight figure file fill film final find "
         "fine finger finish fire firm first fish fist fit fix flag flame flash flat flavour "
         "float flood floor flour flow flower fly focus fog fold follow food fool foot force "
         "forest forget fork form forward found fox frame free fresh friend frighten front fruit "
         "fuel full fun funny furnish future gain game garden gas gate gather general gentle get "
         "gift girl give glad glass globe glove glue goat gold good govern grab grace grain "
         "grand grant grape grass grave great green grey grind grip ground group grow guard "
         "guess guest guide gun habit hair half hall hammer hand hang happen happy harbour hard "
         "harm hat hate have head health hear heart heat heavy hedge height help hidden high "
         "hill history hit hold hole hollow holy home honest honey hook hope horn horse hospital "
         "hot hour house human humble hungry hunt hurry hurt ice idea ill image import inch "
         "include increase indeed industry ink inner insect inside instead iron island issue "
         "jacket jar jaw jelly jewel job join joint joke journey joy judge juice jump just keep "
         "kettle key kick kind king kiss kitchen knee knife knock knot know labour lace lack "
         "ladder lady lake lamp land language large last late laugh law layer lazy lead leaf "
         "learn leather leave left leg lend length less letter level library lid lie life lift "
         "light like limb limit line lion lip liquid list listen little live load loaf local "
         "lock log lonely long look loose lord lose loss loud love low luck lunch machine mad "
         "magic mail main make male man many map march mark market marry mass master match "
         "material matter may meal mean measure meat medicine meet melt member memory mend "
         "mention mercy metal method middle might mild milk mind mine minute mirror miss mist "
         "mix model modern moment money monkey month moon moral more morning most mother motion "
         "mountain mouse mouth move much mud music must nail name narrow nation native nature "
         "near neat neck need needle neighbour nerve nest net never new news next nice night "
         "noble noise none noon north nose note nothing notice now number nurse nut obey object "
         "ocean offer office oil old only open opinion orange order other ought out oven over "
         "owe own pack page pain paint pair pale paper parcel parent park part pass past path "
         "patient pattern pause pay peace pen pencil people pepper perfect perhaps period person "
         "pick picture piece pig pile pin pink pipe pity place plain plan plane plant plate play "
         "please plenty plough pocket point poison pole police polish poor popular port position "
         "possible post pot potato pour powder power praise pray prepare present press pretty "
         "prevent price pride print prison private prize problem produce profit promise proof "
         "proper protect proud prove public pull pump punish pure purple purpose push put "
         "quality quarter queen question quick quiet quite race radio rail rain raise range rank "
         "rapid rare rate rather raw reach read ready real reason receive record red reduce "
         "refuse regard region regret regular relate remain remember remove rent repair repeat "
         "reply report rescue rest result return reward rice rich ride right ring ripe rise "
         "risk river road rock roll roof room root rope rose rough round row royal rub rubber "
         "rude rule run rush sad safe sail salt same sand save say scale scene school science "
         "score screen sea search season seat second secret section see seed seem seize sell "
         "send sense separate serious serve set settle several shade shake shall shape share "
         "sharp shell shelter shine ship shirt shock shoe shoot shop short shoulder shout show "
         "shut side sight sign silence silk silver simple since sing single sink sister sit six "
         "size skin skirt sky sleep slide slight slip slow small smell smile smoke smooth snake "
         "snow soap social soft soil soldier solid some son song soon sort sound soup south "
         "space spare speak special speed spell spend spirit spoon sport spot spread spring "
         "square stage stamp stand star start state station stay steady steal steam steel step "
         "stick still stir stock stone stop store storm story straight strange street stretch "
         "strike string strong study stuff stupid subject succeed such sudden suffer sugar "
         "suggest suit summer sun supply support suppose sure surface surprise sweet swim "
         "swing switch sword table tail take talk tall taste tax teach team tear tell temper "
         "tender tent term test than thank that theory there thick thin thing think third "
         "thirst this thought thread threat throat through throw thumb thunder ticket tide tidy "
         "tie tight time tin tiny tip tired title today toe together tomorrow tone tongue tool "
         "tooth top total touch tough tour toward tower town track trade train travel treat tree "
         "trick trip trouble true trust truth try tube tune turn twice twin twist type ugly "
         "uncle under unit until upon upper urge use usual valley value various vast vegetable "
         "very view village visit voice vote wage wait wake walk wall want war warm warn wash "
         "waste watch water wave wax way weak wealth wear weather week weigh welcome well west "
         "wet wheat wheel when where while whip white whole why wide wife wild will win wind "
         "window wine wing winter wire wise wish woman wonder wood wool word work world worry "
         "worth wound wrap write wrong yard year yellow yes yesterday yet young").split()

tool(id="password-gen", name="Password & passphrase generator", category=CAT,
     summary="Cryptographically random passwords, with the strength worked out",
     explain=("Uses the operating system's secure random source, not Python's ordinary one. "
              "The strength figure is entropy in bits — how many guesses an attacker needs, "
              "expressed as a power of two — and it assumes they know exactly which scheme you "
              "used, which is the right assumption.\n\n"
              "A four-word passphrase from this list is about 39 bits; five words about 49; "
              "six words about 59 and comfortably beyond offline cracking. Length beats "
              "punctuation every time."),
     tags=["password", "passphrase", "diceware", "random", "entropy"],
     params=[Param("style", "Style", "choice", "passphrase",
                   choices=["passphrase", "random characters", "PIN", "hex", "base64"]),
             Param("length", "Words / characters", "int", 5, minimum=1, maximum=256),
             Param("count", "How many", "int", 5, minimum=1, maximum=100),
             Param("separator", "Word separator", "text", "-", width=6),
             Param("symbols", "Include symbols", "bool", True),
             Param("ambiguous", "Allow lookalike characters (0O1lI)", "bool", False)],
     action=lambda d=None, style="passphrase", length=5, count=5, separator="-",
                   symbols=True, ambiguous=False:
         _genpw(style, int(length), int(count), separator, symbols, ambiguous),
     action_label="Generate", input_kind="none")


def _genpw(style, length, count, sep, symbols, ambiguous):
    from .core import clamp
    length, count = clamp(length, 1, 512, 5), clamp(count, 1, 500, 5)
    import math
    out, bits = [], 0.0
    for _ in range(count):
        if style == "passphrase":
            words = [secrets.choice(WORDS) for _ in range(length)]
            out.append(sep.join(words))
            bits = length * math.log2(len(WORDS))
        elif style == "PIN":
            out.append("".join(secrets.choice(string.digits) for _ in range(length)))
            bits = length * math.log2(10)
        elif style == "hex":
            out.append(secrets.token_hex(max(1, length // 2)))
            bits = (max(1, length // 2)) * 8
        elif style == "base64":
            out.append(secrets.token_urlsafe(length))
            bits = length * 6
        else:
            pool = string.ascii_letters + string.digits
            if symbols:
                pool += "!@#$%^&*()-_=+[]{};:,.?/"
            if not ambiguous:
                pool = "".join(c for c in pool if c not in "0O1lI")
            out.append("".join(secrets.choice(pool) for _ in range(length)))
            bits = length * math.log2(len(pool))
    if bits >= 100:
        verdict = "Overkill in a good way."
    elif bits >= 75:
        verdict = "Strong — beyond any realistic offline attack."
    elif bits >= 60:
        verdict = "Good for anything important."
    elif bits >= 45:
        verdict = "Fine for an online account with rate limiting; thin for an encrypted file."
    else:
        verdict = "Weak. Add length."
    return Result(text="\n".join(out),
                  note=f"About {bits:.0f} bits of entropy each "
                       f"(about 2^{bits:.0f} guesses). {verdict}")


tool(id="random", name="Random bytes / keys", category=CAT,
     summary="Secure random data in whatever format you need",
     explain=("For keys, salts, nonces, API tokens and test data. Comes from the operating "
              "system's cryptographic random source (getrandom / BCryptGenRandom), which is "
              "the only kind fit for key material."),
     tags=["random", "key", "token", "salt", "nonce", "uuid"],
     params=[Param("nbytes", "Bytes", "int", 32, minimum=1, maximum=4096),
             Param("fmt", "Format", "choice", "hex",
                   choices=["hex", "base64", "base64 url-safe", "raw bytes", "UUID v4",
                            "C array", "Python bytes"]),
             Param("count", "How many", "int", 1, minimum=1, maximum=100)],
     action=lambda d=None, nbytes=32, fmt="hex", count=1: _rand(int(nbytes), fmt, int(count)),
     action_label="Generate", input_kind="none")


def _rand(nbytes, fmt, count):
    from .core import clamp
    nbytes, count = clamp(nbytes, 1, 1_000_000, 32), clamp(count, 1, 1000, 1)
    import uuid
    lines, blob = [], b""
    for _ in range(count):
        raw = secrets.token_bytes(nbytes)
        blob += raw
        if fmt == "hex":
            lines.append(raw.hex())
        elif fmt == "base64":
            lines.append(base64.b64encode(raw).decode())
        elif fmt == "base64 url-safe":
            lines.append(base64.urlsafe_b64encode(raw).decode().rstrip("="))
        elif fmt == "UUID v4":
            lines.append(str(uuid.uuid4()))
        elif fmt == "C array":
            lines.append("{ " + ", ".join(f"0x{b:02x}" for b in raw) + " }")
        elif fmt == "Python bytes":
            lines.append(repr(raw))
        else:
            lines.append(pretty_hex(raw))
    return Result(text="\n".join(lines), data=blob,
                  note=f"{nbytes} bytes = {nbytes*8} bits each, from the OS random source.")


tool(id="shred", name="Securely delete a file", category=CAT,
     summary="Overwrite then delete — with an honest word about SSDs",
     explain=("Overwrites the file's bytes several times, renames it, then deletes it. On a "
              "mechanical hard drive that genuinely destroys the contents.\n\n"
              "On an SSD or any flash storage it does not, and cannot: wear levelling means "
              "the drive writes your overwrite somewhere else and leaves the original blocks "
              "alone until it feels like reusing them. On flash, full-disk encryption from the "
              "start is the only real answer. Cryptex tells you this rather than pretending."),
     security="On SSDs, USB sticks and SD cards this cannot guarantee the old data is gone. "
              "It is still better than a plain delete, but do not rely on it.",
     tags=["wipe", "erase", "delete", "secure", "ssd"],
     input_kind="file", input_label="File to destroy",
     params=[Param("passes", "Overwrite passes", "int", 3, minimum=1, maximum=35),
             Param("confirm", "Yes, permanently destroy this file", "bool", False)],
     action=lambda path, passes=3, confirm=False: _shred(path, int(passes), confirm),
     action_label="Shred")


def _shred(path, passes, confirm):
    from .core import clamp
    passes = clamp(passes, 1, 35, 3)
    path = need(path, "Pick a file.")
    if not confirm:
        raise ToolError("Tick the confirmation box. This cannot be undone.")
    if not os.path.isfile(path):
        raise ToolError(f"Not a file: {path}")
    size = os.path.getsize(path)
    with open(path, "r+b") as fh:
        for p in range(passes):
            fh.seek(0)
            filler = (lambda n: b"\x00" * n) if p % 3 == 0 else \
                     (lambda n: b"\xff" * n) if p % 3 == 1 else os.urandom
            left = size
            while left > 0:
                n = min(left, CHUNK)
                fh.write(filler(n))
                left -= n
            fh.flush()
            os.fsync(fh.fileno())
    d = os.path.dirname(os.path.abspath(path))
    tmp = os.path.join(d, secrets.token_hex(12))
    os.rename(path, tmp)
    os.unlink(tmp)
    return Result(note=f"{size:,} bytes overwritten {passes} time(s), renamed and deleted.",
                  warn="If this was on an SSD or a USB stick, assume recoverable fragments remain.")


# --------------------------------------------------------------------------
# Password strength
# --------------------------------------------------------------------------

def _pw_strength(data, **_k):
    import math
    pw = to_text(data)
    if not pw:
        raise ToolError("Type a password to check. It is not sent anywhere - the whole "
                        "check runs on your machine.")
    from .hashing import _COMMON_PW
    common = {w.lower() for w in _COMMON_PW}

    lower = any(c.islower() for c in pw)
    upper = any(c.isupper() for c in pw)
    digit = any(c.isdigit() for c in pw)
    symbol = any(not c.isalnum() for c in pw)
    pool = (26 * lower + 26 * upper + 10 * digit + 33 * symbol) or 1
    entropy = len(pw) * math.log2(pool)

    reasons = []
    base = pw.lower()
    stripped = base.rstrip("0123456789!?.")
    if base in common or stripped in common:
        entropy = min(entropy, 12)
        reasons.append("it is on the list of the most common passwords (or one of them with "
                       "digits tacked on) - the very first thing any attacker tries.")
    if len(set(pw)) <= 2 and len(pw) > 3:
        entropy = min(entropy, 10)
        reasons.append("it repeats just one or two characters.")
    if pw.isdigit():
        reasons.append("it is all digits, so there are only ten possibilities per character.")
    if len(pw) < 8:
        reasons.append("it is short - length matters more than anything else.")

    # crack time at 1e10 guesses/sec (a serious offline attack on a fast hash)
    guesses = 2 ** entropy / 2
    secs = guesses / 1e10
    if secs < 1:
        when = "instantly"
    elif secs < 3600:
        when = f"about {secs/60:.0f} minutes" if secs >= 60 else f"about {secs:.0f} seconds"
    elif secs < 86400 * 365:
        when = f"about {secs/86400:.0f} days" if secs >= 86400 else f"about {secs/3600:.0f} hours"
    else:
        years = secs / (86400 * 365)
        when = (f"about {years:.0f} years" if years < 1e6 else
                f"about {years:.0e} years" if years < 1e15 else "effectively forever")

    if entropy < 28:
        rating = "Very weak"
    elif entropy < 40:
        rating = "Weak"
    elif entropy < 60:
        rating = "Reasonable"
    elif entropy < 80:
        rating = "Strong"
    else:
        rating = "Very strong"

    classes = sum([lower, upper, digit, symbol])
    rows = [("Rating", rating),
            ("Estimated entropy", f"{entropy:.0f} bits"),
            ("Length", f"{len(pw)} characters"),
            ("Character types", f"{classes} of 4 (lower/upper/digit/symbol)"),
            ("Time to crack (fast offline)", when)]
    note = ("A rough guide, not a guarantee: it assumes a serious attacker guessing ten "
            "billion times a second against a fast hash. Real strength also depends on "
            "whether the password is truly unpredictable rather than merely long.")
    warn = ""
    if reasons:
        warn = "This password is weak because " + " And ".join(reasons)
    elif entropy < 60:
        warn = ("Fine for something low-stakes, but not for anything that matters. A "
                "four- or five-word passphrase beats this comfortably - see the password "
                "generator.")
    return Result(rows=rows, headers=["", ""], note=note, warn=warn, prefer="table")


tool(id="password-strength", name="Password strength", category=CAT,
     summary="Estimate how strong a password is and how long it would take to crack",
     explain=(
         "Tells you how much unpredictability a password really has, in bits, and turns that "
         "into a plain answer to the only question that matters: how long would it take to "
         "guess. It checks the character mix and length, and cross-references the list of the "
         "most common passwords - because 'Password1!' looks complex to a rule that only "
         "counts character types, and is cracked instantly by one that has seen it before.\n\n"
         "The password is never sent anywhere; the whole check runs locally. The crack-time "
         "figure assumes a determined offline attack - ten billion guesses a second against a "
         "fast hash - so it is deliberately pessimistic, which is the right way to judge a "
         "password.\n\n"
         "If you need a strong one, the password generator makes both random strings and "
         "word-based passphrases."),
     example="Try 'correct horse battery staple' against 'P@ssw0rd'.",
     tags=["password", "strength", "entropy", "zxcvbn", "crack time", "audit"],
     params=[Param("data", "Password", "password", "", width=28)],
     action=lambda data="", **k: _pw_strength(data), action_label="Check", input_kind="text")
