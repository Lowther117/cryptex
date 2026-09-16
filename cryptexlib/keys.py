"""Keys, signatures and certificates — public-key cryptography.

The difference from the Encryption tab: there, one password does everything.
Here there are two keys. What one locks only the other unlocks, so you can
publish one half and keep the other.
"""
from __future__ import annotations

import base64
import datetime
import os

from .core import (Param, Result, ToolError, need, pretty_hex, to_bytes,
                   to_text, tool)

CAT = "Keys & certificates"

EXPLAIN_PK = (
    "Public-key cryptography gives you a matched pair. Anything encrypted with the public key "
    "can only be decrypted with the private one, and anything signed with the private key can "
    "be checked by anyone holding the public one.\n\n"
    "That solves the problem passwords cannot: you can hand your public key to the world and "
    "still be the only person who can read what comes back, or prove that something came from "
    "you. It is what sits underneath HTTPS, signed software, SSH logins and signed email.\n\n"
    "Ed25519 is the modern default — small, fast, hard to use wrongly. RSA is the one every "
    "old system understands; use 3072 bits or more. ECDSA sits in between and is what most "
    "certificate authorities issue.")


def _load_private(pem_text, password=None):
    from cryptography.hazmat.primitives import serialization
    data = to_bytes(pem_text)
    try:
        return serialization.load_pem_private_key(
            data, password=password.encode() if password else None)
    except Exception as exc:
        raise ToolError(f"Could not read that private key ({exc}). "
                        "Paste the whole PEM block including the BEGIN and END lines, "
                        "and give the passphrase if it has one.") from exc


def _load_public(pem_text):
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    data = to_bytes(pem_text)
    for loader in (serialization.load_pem_public_key,
                   serialization.load_ssh_public_key):
        try:
            return loader(data)
        except Exception:
            continue
    try:
        return x509.load_pem_x509_certificate(data).public_key()
    except Exception as exc:
        raise ToolError(f"Could not read that public key or certificate ({exc}).") from exc


tool(id="keygen", name="Generate a key pair", category=CAT,
     summary="Ed25519, RSA or ECDSA, as PEM — and OpenSSH if you want it",
     explain=EXPLAIN_PK,
     security=("The private key is the secret. If you set a passphrase it is encrypted at rest, "
               "which is what you want for anything you keep on disk. Cryptex does not store "
               "keys anywhere — copy them out or save them before you move on."),
     tags=["rsa", "ed25519", "ecdsa", "ssh", "pem", "keypair"],
     params=[Param("algo", "Algorithm", "choice", "Ed25519",
                   choices=["Ed25519", "RSA 2048", "RSA 3072", "RSA 4096",
                            "ECDSA P-256", "ECDSA P-384", "X25519 (key exchange)"]),
             Param("passphrase", "Protect the private key with", "password", "",
                   help="Blank leaves the private key unencrypted on disk."),
             Param("ssh", "Also show the OpenSSH public key", "bool", True),
             Param("comment", "SSH comment", "text", "", width=20)],
     action=lambda d=None, algo="Ed25519", passphrase="", ssh=True, comment="":
         _keygen(algo, passphrase, ssh, comment),
     action_label="Generate", input_kind="none")


def _keygen(algo, passphrase, ssh, comment):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
    if algo == "Ed25519":
        key = ed25519.Ed25519PrivateKey.generate()
    elif algo.startswith("X25519"):
        key = x25519.X25519PrivateKey.generate()
    elif algo.startswith("RSA"):
        key = rsa.generate_private_key(65537, int(algo.split()[1]))
    else:
        curve = ec.SECP256R1() if "256" in algo else ec.SECP384R1()
        key = ec.generate_private_key(curve)
    enc = (serialization.BestAvailableEncryption(passphrase.encode())
           if passphrase else serialization.NoEncryption())
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8, enc).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    parts = [priv.rstrip(), "", pub.rstrip()]
    rows = [("Algorithm", algo),
            ("Private key", "encrypted with your passphrase" if passphrase else "NOT encrypted")]
    if ssh and not algo.startswith("X25519"):
        try:
            sshpub = key.public_key().public_bytes(
                serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
            if comment:
                sshpub += " " + comment
            parts += ["", sshpub]
            rows.append(("OpenSSH public key", "included below"))
        except Exception:
            pass
    rows.append(("Fingerprint (SHA-256)", _fingerprint(key.public_key())))
    return Result(text="\n".join(parts), rows=rows, headers=["", ""],
                  suggested_name="private_key.pem",
                  note="Save the private key somewhere safe. The public half can go anywhere.",
                  warn="" if passphrase else "This private key has no passphrase — anyone who "
                                             "gets the file can use it.")


def _fingerprint(pubkey) -> str:
    import hashlib
    from cryptography.hazmat.primitives import serialization
    try:
        raw = pubkey.public_bytes(serialization.Encoding.OpenSSH,
                                  serialization.PublicFormat.OpenSSH).split()[1]
        digest = hashlib.sha256(base64.b64decode(raw)).digest()
        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    except Exception:
        raw = pubkey.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
        return "SHA256:" + hashlib.sha256(raw).hexdigest()


tool(id="rsa-crypt", name="Encrypt with a public key (RSA)", category=CAT,
     summary="Anyone can lock it; only the private key opens it",
     explain=("RSA can encrypt directly, but only a small amount — about 190 bytes with a "
              "2048-bit key. That is why real systems use it to wrap a random AES key and "
              "encrypt the actual data with AES. For a short message or a key, this is the "
              "tool.\n\nOAEP padding is used, which is the safe modern choice; PKCS#1 v1.5 is "
              "offered only because older systems still require it."),
     security="If your message is longer than the key allows, encrypt the file with a password "
              "in the Encryption tab and use RSA only for the password.",
     tags=["rsa", "oaep", "public key", "asymmetric"],
     params=[Param("key", "Public key (encrypt) or private key (decrypt), PEM", "multiline", ""),
             Param("passphrase", "Private key passphrase", "password", "", only="decode"),
             Param("padding", "Padding", "choice", "OAEP-SHA256",
                   choices=["OAEP-SHA256", "OAEP-SHA1", "PKCS#1 v1.5 (legacy)"])],
     encode=lambda d, key="", padding="OAEP-SHA256", **k: _rsa(d, key, padding, "", False),
     decode=lambda d, key="", passphrase="", padding="OAEP-SHA256":
         _rsa(d, key, padding, passphrase, True),
     encode_label="Encrypt", decode_label="Decrypt", binary_ok=True)


def _rsa_padding(name):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as pad
    if name.startswith("PKCS"):
        return pad.PKCS1v15()
    algo = hashes.SHA1() if name.endswith("SHA1") else hashes.SHA256()
    return pad.OAEP(mgf=pad.MGF1(algorithm=algo), algorithm=algo, label=None)


def _rsa(data, key, padding, passphrase, dec):
    from .core import b64_any
    need(key, "Paste the RSA key (PEM) into the key box.")
    p = _rsa_padding(padding)
    if dec:
        k = _load_private(key, passphrase or None)
        raw = to_bytes(data)
        if not raw.startswith(b"\x00") or True:
            try:
                raw = b64_any(to_text(data))
            except ToolError:
                raw = to_bytes(data)
        try:
            out = k.decrypt(raw, p)
        except Exception as exc:
            raise ToolError(f"Decryption failed ({type(exc).__name__}). Wrong key, wrong "
                            "padding, or the ciphertext is damaged.") from exc
        try:
            return Result(text=out.decode("utf-8"), data=out)
        except UnicodeDecodeError:
            return Result(text=pretty_hex(out), data=out, note="Binary result — use Save.")
    k = _load_public(key)
    raw = to_bytes(data)
    try:
        ct = k.encrypt(raw, p)
    except Exception as exc:
        size = getattr(k, "key_size", 0) // 8
        limit = size - 66 if padding.startswith("OAEP-SHA256") else size - 42 if padding.startswith("OAEP") else size - 11
        raise ToolError(f"RSA could not encrypt {len(raw)} bytes ({exc}). With this key and "
                        f"padding the limit is about {max(limit,0)} bytes. Encrypt the data "
                        "with a password in the Encryption tab and RSA-encrypt the password "
                        "instead — that is what real systems do.") from exc
    return Result(text=base64.b64encode(ct).decode(), data=ct,
                  note=f"{len(ct)} bytes of ciphertext. Only the matching private key can open it.")


tool(id="sign", name="Sign & verify", category=CAT,
     summary="Prove a message came from you and was not altered",
     explain=("A signature is made with the private key and checked with the public one. It "
              "proves two things at once: the message has not changed since it was signed, and "
              "it was signed by whoever holds that private key.\n\n"
              "It does not hide anything — a signed message is still readable by everyone. "
              "Signing and encrypting are different jobs and you often want both."),
     tags=["signature", "ed25519", "rsa-pss", "ecdsa", "verify", "authenticity"],
     params=[Param("key", "Private key (sign) or public key (verify), PEM", "multiline", ""),
             Param("passphrase", "Private key passphrase", "password", "", only="encode"),
             Param("signature", "Signature to check (Base64)", "multiline", "", only="decode")],
     encode=lambda d, key="", passphrase="", **k: _sign(d, key, passphrase),
     decode=lambda d, key="", signature="", **k: _verify(d, key, signature),
     encode_label="Sign", decode_label="Verify", binary_ok=True)


def _sign(data, key, passphrase):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    k = _load_private(need(key, "Paste your private key."), passphrase or None)
    msg = to_bytes(data)
    if isinstance(k, ed25519.Ed25519PrivateKey):
        sig, how = k.sign(msg), "Ed25519"
    elif isinstance(k, rsa.RSAPrivateKey):
        sig = k.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                      salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        how = "RSA-PSS with SHA-256"
    elif isinstance(k, ec.EllipticCurvePrivateKey):
        sig, how = k.sign(msg, ec.ECDSA(hashes.SHA256())), "ECDSA with SHA-256"
    else:
        raise ToolError("That key type cannot sign. Use Ed25519, RSA or ECDSA.")
    return Result(text=base64.b64encode(sig).decode(), data=sig,
                  note=f"{how}. Send this alongside the message, with your public key.")


def _verify(data, key, signature):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    from .core import b64_any
    k = _load_public(need(key, "Paste the signer's public key."))
    sig = b64_any(need(signature, "Paste the signature to check."))
    msg = to_bytes(data)
    try:
        if isinstance(k, ed25519.Ed25519PublicKey):
            k.verify(sig, msg)
        elif isinstance(k, rsa.RSAPublicKey):
            try:
                k.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                               salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            except Exception:
                k.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(k, ec.EllipticCurvePublicKey):
            k.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        else:
            raise ToolError("That key type cannot verify signatures.")
    except ToolError:
        raise
    except Exception:
        return Result(warn="SIGNATURE INVALID. Either the message was altered, the signature "
                           "does not belong to it, or it was made by a different key. "
                           "Do not trust this message.")
    return Result(note="SIGNATURE VALID. This message is byte-for-byte what the holder of that "
                       "private key signed.")


tool(id="inspect-key", name="Inspect a key or certificate", category=CAT,
     summary="What is this PEM? Type, size, subject, dates, fingerprint",
     explain=("Paste any PEM block — private key, public key, certificate, or certificate "
              "signing request — or an OpenSSH public key line, and Cryptex tells you what it "
              "is and everything useful about it, including whether a certificate has expired "
              "and which host names it covers."),
     tags=["x509", "certificate", "pem", "ssh", "fingerprint", "expiry", "san"],
     params=[Param("passphrase", "Passphrase, if the private key has one", "password", "")],
     action=lambda d, passphrase="": _inspect(to_text(d), passphrase),
     action_label="Inspect")


def _inspect(text, passphrase):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    text = need(text.strip(), "Paste a PEM block or an OpenSSH public key.")
    data = text.encode()
    rows, note, warn = [], "", ""

    if "BEGIN CERTIFICATE REQUEST" in text:
        csr = x509.load_pem_x509_csr(data)
        rows = [("Type", "Certificate signing request (CSR)"),
                ("Subject", csr.subject.rfc4514_string()),
                ("Signature valid", "yes" if csr.is_signature_valid else "NO"),
                ("Public key", _describe_key(csr.public_key())),
                ("Fingerprint", _fingerprint(csr.public_key()))]
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            rows.append(("Names requested", ", ".join(san.value.get_values_for_type(x509.DNSName))))
        except x509.ExtensionNotFound:
            pass
        return Result(rows=rows, headers=["", ""], note="A request for a certificate, not a certificate.")

    if "BEGIN CERTIFICATE" in text:
        cert = x509.load_pem_x509_certificate(data)
        now = datetime.datetime.now(datetime.timezone.utc)
        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        days = (na - now).days
        rows = [("Type", "X.509 certificate"),
                ("Subject", cert.subject.rfc4514_string()),
                ("Issuer", cert.issuer.rfc4514_string()),
                ("Self-signed", "yes" if cert.subject == cert.issuer else "no"),
                ("Serial", hex(cert.serial_number)),
                ("Valid from", nb.strftime("%d %b %Y %H:%M UTC")),
                ("Valid to", na.strftime("%d %b %Y %H:%M UTC")),
                ("Signature algorithm", cert.signature_algorithm_oid._name),
                ("Public key", _describe_key(cert.public_key())),
                ("SHA-256 fingerprint", cert.fingerprint(hashes.SHA256()).hex(":"))]
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            rows.append(("Covers", ", ".join(san.value.get_values_for_type(x509.DNSName)) or "-"))
        except x509.ExtensionNotFound:
            pass
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            rows.append(("Certificate authority", "yes" if bc.ca else "no"))
        except x509.ExtensionNotFound:
            pass
        if days < 0:
            warn = f"EXPIRED {abs(days)} days ago."
        elif days < 30:
            warn = f"Expires in {days} days."
        else:
            note = f"Valid for another {days} days."
        return Result(rows=rows, headers=["", ""], note=note, warn=warn)

    if "PRIVATE KEY" in text:
        k = _load_private(text, passphrase or None)
        pub = k.public_key()
        rows = [("Type", "Private key"),
                ("Encrypted at rest", "yes" if "ENCRYPTED" in text else "no"),
                ("Algorithm", _describe_key(pub)),
                ("Fingerprint", _fingerprint(pub))]
        pubpem = pub.public_bytes(serialization.Encoding.PEM,
                                  serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return Result(rows=rows, headers=["", ""], text=pubpem,
                      note="Matching public key shown above.",
                      warn="" if "ENCRYPTED" in text else "Not passphrase-protected.")

    pub = _load_public(text)
    rows = [("Type", "Public key"), ("Algorithm", _describe_key(pub)),
            ("Fingerprint", _fingerprint(pub))]
    return Result(rows=rows, headers=["", ""])


def _describe_key(pub):
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa, x25519
    if isinstance(pub, rsa.RSAPublicKey):
        n = pub.key_size
        note = " (too small — use 3072 or more)" if n < 2048 else ""
        return f"RSA {n} bits{note}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ECDSA {pub.curve.name}"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(pub, x25519.X25519PublicKey):
        return "X25519 (key exchange only)"
    return type(pub).__name__


tool(id="selfsigned", name="Self-signed certificate / CSR", category=CAT,
     summary="Make a test certificate, or a request to send to a CA",
     explain=("A self-signed certificate is one that vouches for itself. Browsers will not "
              "trust it, which is the point — it is for local development, internal tools and "
              "testing TLS configuration.\n\n"
              "A CSR is the other half of the real process: you keep the private key and send "
              "the CSR to a certificate authority, who signs it and sends back a certificate "
              "the world will trust."),
     tags=["x509", "tls", "https", "csr", "openssl", "localhost"],
     params=[Param("what", "Produce", "choice", "Self-signed certificate",
                   choices=["Self-signed certificate", "Certificate signing request (CSR)"]),
             Param("common_name", "Common name / host", "text", "localhost", width=24),
             Param("names", "Also covers (comma separated)", "text", "127.0.0.1", width=24),
             Param("org", "Organisation", "text", "", width=20),
             Param("country", "Country code", "text", "GB", width=6),
             Param("days", "Valid for (days)", "int", 825, minimum=1, maximum=7300),
             Param("algo", "Key", "choice", "RSA 2048",
                   choices=["RSA 2048", "RSA 4096", "ECDSA P-256", "Ed25519"])],
     action=lambda d=None, what="Self-signed certificate", common_name="localhost",
                   names="127.0.0.1", org="", country="GB", days=825, algo="RSA 2048":
         _cert(what, common_name, names, org, country, int(days), algo),
     action_label="Create", input_kind="none")


def _cert(what, cn, names, org, country, days, algo):
    from .core import clamp
    days = clamp(days, 1, 7300, 825)
    cn = (cn or "localhost").strip() or "localhost"
    if len(cn) > 64:
        raise ToolError("A certificate common name can be at most 64 characters. "
                        "Put the longer names in 'Also covers' instead.")
    country = (country or "").strip().upper()
    if country and len(country) != 2:
        raise ToolError("The country has to be a two-letter code, such as GB or US.")
    org = (org or "").strip()[:64]
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.x509.oid import NameOID
    if algo == "Ed25519":
        key, halgo = ed25519.Ed25519PrivateKey.generate(), None
    elif algo.startswith("ECDSA"):
        key, halgo = ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()
    else:
        key, halgo = rsa.generate_private_key(65537, int(algo.split()[1])), hashes.SHA256()

    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if country:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    subject = x509.Name(attrs)

    alt = []
    for n in [cn] + [x.strip() for x in (names or "").split(",") if x.strip()]:
        if not n:
            continue
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(n)))
            continue
        except ValueError:
            pass
        # Certificates carry host names in punycode, not in Unicode
        try:
            label = n if n.isascii() else ".".join(
                part.encode("idna").decode() if part and not part.isascii() else part
                for part in n.split("."))
            alt.append(x509.DNSName(label))
        except (UnicodeError, ValueError) as exc:
            raise ToolError(f"'{n}' is not a usable host name for a certificate "
                            f"({exc}). Host names must be ASCII; Cryptex converts "
                            "accented names to punycode for you where it can.") from exc
    san = x509.SubjectAlternativeName(alt)

    privpem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    if what.startswith("Certificate signing"):
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(subject).add_extension(san, critical=False)
               .sign(key, halgo))
        pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        return Result(text=privpem.rstrip() + "\n\n" + pem.rstrip(),
                      rows=[("Subject", subject.rfc4514_string()),
                            ("Names", ", ".join(str(a.value) for a in alt)),
                            ("Key", algo)],
                      headers=["", ""], suggested_name="request.csr",
                      note="Send the CSR to your certificate authority. Keep the private key.")
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, halgo))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return Result(text=privpem.rstrip() + "\n\n" + pem.rstrip(),
                  rows=[("Subject", subject.rfc4514_string()),
                        ("Covers", ", ".join(str(a.value) for a in alt)),
                        ("Key", algo), ("Valid for", f"{days} days"),
                        ("SHA-256 fingerprint", cert.fingerprint(hashes.SHA256()).hex(":"))],
                  headers=["", ""], suggested_name="cert.pem",
                  note="Private key first, then the certificate. Save them as two files.",
                  warn="Self-signed: browsers and clients will not trust it unless you add it "
                       "to their trust store yourself.")


tool(id="dh", name="Shared secret (Diffie-Hellman)", category=CAT,
     summary="Two people derive the same key without ever sending it",
     explain=("The trick that makes HTTPS possible. Each side generates a key pair and sends "
              "only the public half. Each then combines their own private key with the other's "
              "public key, and both arrive at the same secret — which never crossed the wire "
              "and cannot be worked out by anyone who watched.\n\n"
              "Generate an X25519 key pair in 'Generate a key pair', swap public keys, then "
              "paste your private key and their public key here."),
     tags=["ecdh", "x25519", "key exchange", "shared secret", "hkdf"],
     params=[Param("mine", "My private key (PEM)", "multiline", ""),
             Param("theirs", "Their public key (PEM)", "multiline", ""),
             Param("passphrase", "My key's passphrase", "password", ""),
             Param("info", "Context label for HKDF", "text", "cryptex", width=16)],
     action=lambda d=None, mine="", theirs="", passphrase="", info="cryptex":
         _dh(mine, theirs, passphrase, info),
     action_label="Derive shared key", input_kind="none")


def _dh(mine, theirs, passphrase, info):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, x25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    priv = _load_private(need(mine, "Paste your private key."), passphrase or None)
    pub = _load_public(need(theirs, "Paste their public key."))
    if isinstance(priv, x25519.X25519PrivateKey):
        shared = priv.exchange(pub)
        how = "X25519"
    elif isinstance(priv, ec.EllipticCurvePrivateKey):
        shared = priv.exchange(ec.ECDH(), pub)
        how = f"ECDH on {priv.curve.name}"
    else:
        raise ToolError("Diffie-Hellman needs an X25519 or ECDSA/EC key, not "
                        f"{type(priv).__name__}. Generate an X25519 pair.")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=info.encode()).derive(shared)
    return Result(text=key.hex(), data=key,
                  rows=[("Method", how), ("Raw shared point", shared.hex()),
                        ("Derived key (HKDF-SHA256)", key.hex())],
                  headers=["", ""],
                  note="Both sides get this same value. Use it as the key for AES-256-GCM.",
                  warn="On its own this does not prove who you are talking to — that is what "
                       "signatures and certificates are for.")
