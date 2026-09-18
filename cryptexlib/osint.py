"""Forensics and OSINT utilities - offline indicator handling.

None of these touch the network. They are the offline, data-manipulation half
of what an OSINT or incident-response job needs: taking an indicator someone
handed you - a defanged URL, a raw timestamp, an IP range, a pile of email
headers, a number that might be a card - and turning it into something you can
read and reason about. The "go and look it up online" half is a different kind
of tool and deliberately not here.
"""
from __future__ import annotations

from .core import Param, Result, ToolError, clamp, need, to_text, tool

CAT = "Forensics & OSINT"


# --------------------------------------------------------------------------
# Defang / refang indicators of compromise
# --------------------------------------------------------------------------

def _defang(text, **_k):
    s = to_text(text)
    # order matters: protocols first, then dots and @, then brackets left clean
    s = s.replace("http://", "hxxp://").replace("https://", "hxxps://")
    s = s.replace("ftp://", "fxp://")
    s = s.replace("@", "[at]")
    s = s.replace(".", "[.]")
    return Result(text=s, prefer="text",
                  note="Defanged - safe to paste into a report, ticket or email without a "
                       "client turning it into a live, clickable link.")


def _refang(text, **_k):
    s = to_text(text)
    for a, b in [("hxxps://", "https://"), ("hxxp://", "http://"), ("hXXps://", "https://"),
                 ("hXXp://", "http://"), ("fxp://", "ftp://"), ("[://]", "://"),
                 ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
                 ("{dot}", "."), (" dot ", "."), ("[at]", "@"), ("(at)", "@"),
                 ("{at}", "@"), (" at ", "@"), ("[:]", ":"), ("[//]", "//")]:
        s = s.replace(a, b)
        s = s.replace(a.upper(), b)
    return Result(text=s, prefer="text",
                  note="Refanged back to the real indicator.",
                  warn="Now live and clickable - do not click a hostile URL by accident.")


tool(id="defang", name="Defang / refang indicators", category=CAT,
     summary="Make a URL, IP or email safe to share - or turn a defanged one back",
     explain=(
         "When you put a malicious URL or IP in a report, an email or a ticket, you do not "
         "want it to become a live clickable link that a colleague fat-fingers into. Defanging "
         "is the convention that fixes that: `http` becomes `hxxp`, dots become `[.]`, the `@` "
         "in an email becomes `[at]`. The indicator is still perfectly readable, just inert.\n\n"
         "Encode defangs; decode (refang) reverses it, understanding the whole zoo of styles "
         "people use - `[.]`, `(.)`, `[dot]`, ` dot `, `hxxp`, `hXXp` and so on - so you can "
         "paste in a defanged indicator from anywhere and get the real one back.\n\n"
         "Standard practice in threat intel and incident response, and the reason a shared "
         "indicator does not become an accidental click."),
     example="https://evil.example.com/pay  ->  hxxps://evil[.]example[.]com/pay",
     tags=["defang", "refang", "ioc", "threat intel", "indicator", "malware", "url", "osint"],
     encode=_defang, decode=_refang,
     encode_label="Defang", decode_label="Refang")


# --------------------------------------------------------------------------
# Timestamp decoder
# --------------------------------------------------------------------------

def _timestamps(data, **_k):
    import datetime as dt
    raw = to_text(data).strip().replace(",", "").replace("_", "")
    if not raw:
        raise ToolError("Paste a timestamp number to decode.")
    # allow hex (0x... or a FILETIME in hex)
    try:
        n = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    except ValueError:
        raise ToolError("That is not a whole number. This decodes numeric timestamps; for a "
                        "written date like 2026-09-18, the TOTP tool takes those.")
    if n < 0:
        raise ToolError("A timestamp cannot be negative.")

    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    rows, plausible = [], []
    lo = dt.datetime(1995, 1, 1, tzinfo=dt.timezone.utc)
    hi = dt.datetime(2040, 1, 1, tzinfo=dt.timezone.utc)

    def add(label, when, note=""):
        if when is None:
            rows.append((label, "out of range", note))
            return
        stamp = f"{when:%Y-%m-%d %H:%M:%S} UTC"
        good = lo <= when <= hi
        rows.append((label, stamp + ("  ✓" if good else ""), note))
        if good:
            plausible.append((label, stamp))

    def safe(seconds_from_epoch):
        try:
            return epoch + dt.timedelta(seconds=seconds_from_epoch)
        except (OverflowError, OSError, ValueError):
            return None

    add("Unix seconds", safe(n))
    add("Unix milliseconds", safe(n / 1_000))
    add("Unix microseconds", safe(n / 1_000_000))
    add("Unix nanoseconds", safe(n / 1_000_000_000))
    # Windows FILETIME: 100-ns ticks since 1601-01-01
    add("Windows FILETIME", safe(n / 10_000_000 - 11_644_473_600),
        "100-ns ticks since 1601")
    # Mac / Cocoa absolute time: seconds since 2001-01-01
    add("Apple / Cocoa (2001)", safe(n + 978_307_200), "seconds since 2001")
    # Chrome/WebKit: microseconds since 1601
    add("WebKit / Chrome", safe(n / 1_000_000 - 11_644_473_600),
        "microseconds since 1601")

    note = ("A tick ✓ marks the readings that land in a sensible date range (1995-2040) - "
            "usually only one does, and that is almost certainly the right interpretation.")
    if len(plausible) == 1:
        note = f"This is almost certainly {plausible[0][0]}: {plausible[0][1]}."
    return Result(rows=rows, headers=["Interpreted as", "Date", "Notes"], prefer="table",
                  note=note)


tool(id="timestamps", name="Timestamp decoder", category=CAT,
     summary="Turn a raw number into a date - Unix, Windows FILETIME, Apple, WebKit",
     explain=(
         "Logs, databases, file metadata and forensic artefacts all count time from different "
         "starting points in different units, so the same moment shows up as wildly different "
         "numbers. This takes the number and shows what date it is under each of the common "
         "schemes at once.\n\n"
         "It knows Unix time in seconds, milliseconds, microseconds and nanoseconds; Windows "
         "FILETIME (100-nanosecond ticks since 1601, what you get out of the registry and the "
         "event log); Apple's Cocoa time (seconds since 2001); and WebKit/Chrome time "
         "(microseconds since 1601, used in browser history). Paste decimal or hex.\n\n"
         "Usually only one reading lands in a believable date range, and it ticks that one - "
         "which is how you tell which clock the number came from."),
     example="1758153600  or  0x01DC2A...  or a 17-digit Chrome value",
     tags=["timestamp", "epoch", "unix time", "filetime", "forensics", "date", "webkit"],
     action=_timestamps, action_label="Decode", input_kind="text")


# --------------------------------------------------------------------------
# IP / CIDR toolkit
# --------------------------------------------------------------------------

def _ip_tools(data, **_k):
    import ipaddress
    raw = to_text(data).strip()
    if not raw:
        raise ToolError("Paste an IP address, a CIDR range, or an integer to interpret.")

    # a bare integer -> IP address
    if raw.isdigit():
        n = int(raw)
        try:
            addr = ipaddress.ip_address(n)
        except ValueError:
            raise ToolError("That integer is out of range for both IPv4 and IPv6.")
        return _ip_single(addr, extra=[("From integer", str(n))])

    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ToolError(f"Not a valid network: {exc}")
        hosts = net.num_addresses
        rows = [("Network", str(net.network_address)),
                ("Prefix", f"/{net.prefixlen}"),
                ("Netmask", str(net.netmask)),
                ("Wildcard", str(net.hostmask)),
                ("Addresses", f"{hosts:,}")]
        if net.version == 4 and hosts >= 2:
            rows.append(("Usable range", f"{net.network_address + 1}  -  "
                                         f"{net.broadcast_address - 1}"))
            rows.append(("Broadcast", str(net.broadcast_address)))
        else:
            rows.append(("Range", f"{net[0]}  -  {net[-1]}"))
        rows.append(("First / last", f"{net[0]}  /  {net[-1]}"))
        rows.append(("Kind", _ip_kind(net.network_address)))
        return Result(rows=rows, headers=["", ""], prefer="table",
                      note=f"IPv{net.version} network holding {hosts:,} address(es).")

    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        raise ToolError("Not a valid IP address, CIDR range or integer.")
    return _ip_single(addr)


def _ip_kind(addr):
    bits = []
    if addr.is_private:
        bits.append("private")
    if addr.is_loopback:
        bits.append("loopback")
    if addr.is_link_local:
        bits.append("link-local")
    if addr.is_multicast:
        bits.append("multicast")
    if addr.is_reserved:
        bits.append("reserved")
    if getattr(addr, "is_global", False):
        bits.append("global / public")
    return ", ".join(bits) or "unspecified"


def _ip_single(addr, extra=None):
    rows = list(extra or [])
    rows.append(("Address", str(addr)))
    rows.append(("Version", f"IPv{addr.version}"))
    rows.append(("As integer", f"{int(addr):,}"))
    rows.append(("Hex", hex(int(addr))))
    if addr.version == 6:
        rows.append(("Expanded", addr.exploded))
        rows.append(("Compressed", addr.compressed))
    else:
        rows.append(("Reverse DNS", addr.reverse_pointer))
    rows.append(("Kind", _ip_kind(addr)))
    return Result(rows=rows, headers=["", ""], prefer="table",
                  note=f"IPv{addr.version} address.")


tool(id="ip-tools", name="IP / CIDR toolkit", category=CAT,
     summary="Normalise an address, expand a range, convert to and from an integer",
     explain=(
         "Everything you routinely need to do to an IP address or a subnet, offline. Give it a "
         "single address and it shows the version, the integer and hex forms, the reverse-DNS "
         "name, the fully-expanded IPv6, and whether it is public, private, loopback, "
         "link-local, multicast or reserved.\n\n"
         "Give it a CIDR range like `192.168.1.0/24` and it works out the netmask, the "
         "wildcard mask, how many addresses it holds, the usable host range and the broadcast "
         "address. Give it a plain integer and it turns it back into an address - which is how "
         "IPs are often stored in databases and logs.\n\n"
         "All from Python's own network library, so the maths is exactly right."),
     example="8.8.8.8   or   10.0.0.0/8   or   3232235521",
     tags=["ip", "cidr", "subnet", "netmask", "ipv6", "network", "forensics"],
     action=_ip_tools, action_label="Analyse", input_kind="text")


# --------------------------------------------------------------------------
# URL dissector
# --------------------------------------------------------------------------

_TRACKERS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
             "utm_id", "utm_name", "utm_cid", "utm_reader", "utm_referrer",
             "fbclid", "gclid", "gclsrc", "dclid", "gbraid", "wbraid", "msclkid",
             "mc_cid", "mc_eid", "yclid", "igshid", "ttclid", "twclid", "_hsenc",
             "_hsmi", "hsctatracking", "vero_id", "oly_anon_id", "oly_enc_id",
             "wickedid", "ref", "ref_src", "ref_url", "spm", "scm", "s_cid",
             "cmpid", "campaign_id", "ncid", "sr_share"}


def _url_dissect(data, **_k):
    from urllib.parse import urlsplit, parse_qsl, urlunsplit, urlencode, unquote
    raw = to_text(data).strip()
    if not raw:
        raise ToolError("Paste a URL to take apart.")
    if "://" not in raw:
        raw = "http://" + raw
    try:
        u = urlsplit(raw)
        host, port = u.hostname or "", u.port
    except ValueError:
        raise ToolError("That does not parse as a URL - check for stray characters, a bad "
                        "port, or brackets that are not a valid IPv6 host.")
    rows = [("Scheme", u.scheme), ("Host", host),
            ("Port", str(port) if port else "(default)"),
            ("Path", unquote(u.path) or "/")]
    if u.username or u.password:
        rows.append(("Credentials in URL", f"{u.username or ''}:{'***' if u.password else ''}"))
    if u.fragment:
        rows.append(("Fragment", unquote(u.fragment)))

    params = parse_qsl(u.query, keep_blank_values=True)
    kept, stripped = [], []
    for k, v in params:
        (stripped if k.lower() in _TRACKERS else kept).append((k, v))
    for k, v in params:
        rows.append((f"  ?{k}", unquote(v)))

    clean = urlunsplit((u.scheme, u.netloc, u.path, urlencode(kept), ""))
    note = "Broken into its parts."
    if stripped:
        note = (f"Broken apart, and {len(stripped)} tracking parameter(s) removed: "
                + ", ".join(k for k, _ in stripped) + ".")
        rows.append(("Cleaned URL", clean))
    return Result(text=clean if stripped else raw, rows=rows, headers=["Part", "Value"],
                  prefer="table", note=note)


tool(id="url-dissect", name="URL dissector", category=CAT,
     summary="Split a URL into its parts and strip tracking parameters",
     explain=(
         "Pulls a URL apart into scheme, host, port, path, query and fragment, decoding the "
         "percent-encoding as it goes so you can actually read what is in there - including "
         "the giveaways, like a username and password embedded in the link, or a suspicious "
         "host hiding behind a long path.\n\n"
         "It also spots the tracking parameters - the `utm_*` tags, `fbclid`, `gclid` and the "
         "rest of the click-identifiers marketers and networks bolt on - lists them, and hands "
         "back a cleaned URL with them removed. Good for seeing where a link really goes and "
         "for stripping the tracking off one before you share it."),
     example="https://shop.example.com/item?id=42&utm_source=email&fbclid=abc",
     tags=["url", "parse", "tracking", "utm", "privacy", "querystring", "osint"],
     action=_url_dissect, action_label="Dissect", input_kind="text")


# --------------------------------------------------------------------------
# Email header analyser
# --------------------------------------------------------------------------

def _email_headers(data, **_k):
    import email
    from email import policy
    import re
    raw = to_text(data)
    if not raw.strip():
        raise ToolError("Paste the raw email headers (everything above the message body).")
    msg = email.message_from_string(raw, policy=policy.default)

    rows = []
    for h in ("From", "To", "Cc", "Subject", "Date", "Message-ID", "Return-Path",
              "Reply-To"):
        v = msg.get(h)
        if v:
            rows.append((h, str(v)[:200]))

    # authentication results
    auth = msg.get("Authentication-Results", "")
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(mech + r"=(\w+)", auth, re.I)
        if m:
            rows.append((mech.upper(), m.group(1)))

    # Received hops, oldest last in the header - reverse to show the journey
    received = msg.get_all("Received", [])
    hops = []
    ip_re = re.compile(r"[\[(]?(\d{1,3}(?:\.\d{1,3}){3})[\])]?")
    for r in reversed(received):
        r1 = " ".join(r.split())
        ip = ip_re.search(r1)
        frm = re.search(r"from\s+([^\s;]+)", r1, re.I)
        hops.append((frm.group(1)[:40] if frm else "?",
                     ip.group(1) if ip else "",
                     r1[-40:] if ";" not in r1 else r1.split(";")[-1].strip()[:40]))

    origin = ""
    for _frm, ip, _t in hops:
        if ip and not ip.startswith(("10.", "192.168.", "127.")) and not ip.startswith("172."):
            origin = ip
            break
    if origin:
        rows.append(("Likely originating IP", origin))

    hop_rows = [(str(i + 1), frm, ip, when) for i, (frm, ip, when) in enumerate(hops)]
    text_lines = ["Delivery path (first hop = origin):"]
    for i, frm, ip, when in hop_rows:
        text_lines.append(f"  {i}. {frm}  {ip}  {when}")
    if not hops:
        text_lines.append("  (no Received headers found)")

    note = f"{len(hops)} mail hop(s)." + (f" Traffic appears to originate at {origin}."
                                          if origin else "")
    warn = None
    spf = next((v for k, v in rows if k == "SPF"), "")
    dkim = next((v for k, v in rows if k == "DKIM"), "")
    if spf.lower() == "fail" or dkim.lower() == "fail":
        warn = ("SPF or DKIM failed - the sender may be forged. Treat the From address with "
                "suspicion.")
    return Result(text="\n".join(text_lines), rows=rows, headers=["Header", "Value"],
                  prefer="table", note=note, warn=warn)


tool(id="email-headers", name="Email header analyser", category=CAT,
     summary="Read raw email headers - the delivery path, the real sender, SPF/DKIM",
     explain=(
         "Every email carries a stack of `Received:` headers, one per mail server it passed "
         "through, and together they are the envelope's paper trail. This reads them in order "
         "- first hop is where the message actually started - and pulls out the server names, "
         "the IP addresses and the timestamps, so you can see the real route rather than the "
         "From address, which is trivially forged.\n\n"
         "It surfaces the headers that matter (From, Return-Path, Message-ID, Date), reports "
         "the SPF, DKIM and DMARC results if the receiving server recorded them, and picks out "
         "the likely originating public IP. If SPF or DKIM failed, it says so - that is the "
         "clearest single sign of a spoofed sender.\n\n"
         "Paste everything above the message body. It all stays on your machine."),
     example="Paste the full headers from 'View source' / 'Show original'.",
     tags=["email", "headers", "received", "spf", "dkim", "spoof", "phishing", "forensics"],
     params=[Param("data", "Raw headers", "multiline", "", width=50)],
     action=lambda data="", **k: _email_headers(data), action_label="Analyse",
     input_kind="text")


# --------------------------------------------------------------------------
# Identifier validators
# --------------------------------------------------------------------------

def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 2:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _card_brand(num: str) -> str:
    n = "".join(c for c in num if c.isdigit())
    if n.startswith("4") and len(n) in (13, 16, 19):
        return "Visa"
    if (n[:2] in {str(x) for x in range(51, 56)} or
            (len(n) >= 4 and 2221 <= int(n[:4]) <= 2720)) and len(n) == 16:
        return "Mastercard"
    if n[:2] in ("34", "37") and len(n) == 15:
        return "American Express"
    if n[:2] in ("36", "38", "30") and len(n) in (14, 16):
        return "Diners Club"
    if (n.startswith("6011") or n[:2] == "65") and len(n) == 16:
        return "Discover"
    return ""


def _iban_ok(iban: str) -> bool:
    s = "".join(iban.split()).upper()
    if len(s) < 15 or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(int(c, 36)) if c.isalpha() else c for c in rearranged)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


def _isbn_ok(num: str):
    d = "".join(c for c in num if c.isdigit() or c in "Xx")
    if len(d) == 10:
        total = sum((10 - i) * (10 if c in "Xx" else int(c)) for i, c in enumerate(d))
        return total % 11 == 0, "ISBN-10"
    if len(d) == 13:
        total = sum((1 if i % 2 == 0 else 3) * int(c) for i, c in enumerate(d))
        return total % 10 == 0, "ISBN-13"
    return None, ""


def _validate_id(data, **_k):
    raw = to_text(data).strip()
    nospace = "".join(raw.split())
    digits = "".join(c for c in raw if c.isdigit())
    if not raw:
        raise ToolError("Paste a number to check - a card number, IMEI, IBAN or ISBN.")
    rows = []

    iban_candidate = (len(nospace) >= 15 and nospace[:2].isalpha()
                      and nospace[2:4].isdigit())
    isbn_ok, isbn_kind = _isbn_ok(raw)
    is_isbn = isbn_ok is not None and (isbn_kind == "ISBN-10"
                                       or digits.startswith(("978", "979")))

    if iban_candidate:
        rows.append(("IBAN check (mod-97)", "valid ✓" if _iban_ok(raw) else "FAILS ✗"))
    if is_isbn:
        rows.append((f"{isbn_kind} check digit", "valid ✓" if isbn_ok else "FAILS ✗"))

    # Luhn / card only when it is plausibly a card or IMEI - never for an IBAN or ISBN,
    # which would only ever produce a misleading "fails"
    if not iban_candidate and not is_isbn and digits:
        brand = _card_brand(digits)
        if brand or len(digits) in (13, 14, 15, 16, 19):
            if brand:
                label = f"Card number ({brand})"
            elif len(digits) == 15:
                label = "IMEI or 15-digit number"
            else:
                label = "Card-length number"
            rows.append((label + " - Luhn check",
                         "valid ✓" if _luhn_ok(digits) else "FAILS ✗"))

    if not rows:
        rows.append(("Result", "nothing recognised - not a card, IMEI, IBAN or ISBN length"))
    note = ("A check digit only proves the number is internally consistent - that it was not "
            "mistyped. It does not prove the card, phone or account actually exists.")
    return Result(rows=rows, headers=["Check", "Result"], prefer="table", note=note)

tool(id="validate-id", name="Identifier validator", category=CAT,
     summary="Check the check-digit on a card number, IMEI, IBAN or ISBN",
     explain=(
         "Most long identifiers carry a check digit - an extra digit computed from the others "
         "so that a single typo is caught immediately. This runs the right check for whatever "
         "you paste.\n\n"
         "Card numbers and IMEIs use the Luhn formula (and it names the card brand from the "
         "leading digits). IBANs use a mod-97 test over the whole account number. ISBN-10 and "
         "ISBN-13 each have their own weighted sum. \n\n"
         "One honest limit worth stating: a passing check digit only means the number is "
         "well-formed and was not fat-fingered. It says nothing about whether the card, phone "
         "or bank account is real or active - only the issuer knows that."),
     example="4111 1111 1111 1111  (a Visa test number)",
     tags=["luhn", "credit card", "imei", "iban", "isbn", "checksum", "validate"],
     action=_validate_id, action_label="Check", input_kind="text")
