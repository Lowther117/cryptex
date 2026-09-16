# Cryptex

An encoder, decoder and cryptography toolbox for Windows and macOS. 121 tools
in one window: representation changes, historical ciphers with the solvers that
break them, a full Enigma machine, real authenticated encryption, hashing,
public keys and certificates, and interop with the formats other software
speaks - age, QR codes and PKCS#12. Plus steganography for images,
audio and text, one-time codes and split secrets, and a set of radio decoders -
slow-scan television, RTTY, PSK31 and AX.25 packet - that work from a file, from
a video, or live off the air as it arrives.

Everything runs on your own machine. Nothing is uploaded, and no password, key
or file leaves the computer.

---

## Which file do I use?

| File | When |
|---|---|
| `build-exe.bat` | **Windows.** Double-click once. Installs Python if it is missing, installs every dependency, and produces `dist\Cryptex.exe` — one standalone file you can copy anywhere. |
| `build-app.command` | **macOS.** Double-click once. Installs Homebrew and Python if they are missing, installs every dependency, and produces `dist/Cryptex.app`. Drag it to Applications. |
| `run.bat` | Windows, run from source without building an exe. Sets up a virtual environment the first time. |
| `run.command` | macOS, run from source without building an app. |
| `python cryptex.py` | Any platform, if you already have Python 3.9+ with tkinter and the requirements installed. |
| `Cryptex selftest` | Runs all 119 tools and writes `cryptex-selftest.txt` (`python cryptex.py selftest` does the same from source). The build scripts do this for you and refuse to claim success if anything fails. |

The repository is deliberately flat — no Windows/Mac subfolders. The extension
already says which operating system a file is for, and `%~dp0` / `$(dirname
"$0")` assumptions break the moment files move.

**First build on a clean machine takes a few minutes** (Python, Homebrew,
wheels, PyInstaller). After that it is about ninety seconds. Watch
`build-win-log.txt` / `build-mac-log.txt` if you want the detail; on failure the
last forty lines are printed for you.

---

## The three things people call "encryption"

Cryptex is organised around a distinction worth being strict about, because
mixing these up is where most confusion starts.

**Encoding** changes how data is *written*. Base64, hex, URL escapes, Morse.
Anyone can undo it, instantly, with no key. It is not secrecy — it exists so
that awkward data survives channels that expect plain text. If something
"looks encrypted" and turns out to be Base64, it was never protecting anything.

**Hashing** produces a fixed-length fingerprint and cannot be undone at all.
There is no decrypt button for SHA-256, here or in any other program, because
the information is genuinely gone. Hashes are for checking that a file arrived
intact, comparing two things without sending them, and storing passwords.

**Encryption** hides the contents and needs a key to reverse. That is the
Encryption and Keys tabs, and only those.

When you do not know which one you are holding, open **What is this?** and paste
it in. It ranks the possibilities, says why, and tells you which tool to use
next.

---

## What is in it

### Identify

| Tool | What it does |
|---|---|
| **Auto-solve** | Try everything, in every order, and rank what comes out |
| **What is this?** | Paste anything — get a ranked guess and which tool to use next |

### Encodings

| Tool | What it does |
|---|---|
| **A1Z26 (letter numbers)** | A=1, B=2 ... Z=26 - the first substitution anyone invents |
| **Bacon's cipher** | Each letter as five A/B symbols — the original steganography |
| **Base16 / Hex** | Two hex digits per byte — the plainest possible view of data |
| **Base32** | Case-insensitive base — TOTP secrets, onion addresses |
| **Base45** | The compact alphabet behind QR codes and EU digital certificates |
| **Base58** | Bitcoin's base — no 0, O, I or l to misread |
| **Base62 / Base36** | Short IDs - the alphabet behind link shorteners |
| **Base64** | The everyday way to carry binary through text-only channels |
| **Base85 / Ascii85** | Denser than Base64 — PDF, git binary patches |
| **Baudot / ITA2 (5-bit teleprinter)** | The telex code — 5 bits per character with letter/figure shifts |
| **Binary / octal / decimal bytes** | Every byte written out as a number |
| **Braille (Grade 1)** | Uncontracted braille using the Unicode braille block |
| **Change case** | Upper, lower, title, sentence, snake, kebab, camel |
| **Compress / decompress** | gzip, zlib, deflate, bzip2, xz - and it works out which |
| **HTML entities** | &amp; &lt; &#169; — text that will not break a web page |
| **Leetspeak** | 4 for a, 3 for e — password-list substitutions |
| **Morse code** | Dots and dashes, with prosigns and a slash for word breaks |
| **NATO phonetic alphabet** | Alfa Bravo Charlie — for reading a code down the phone |
| **Punycode / IDNA** | How non-English domain names are stored (xn--…) |
| **Quoted-printable** | =3D in email bodies — mostly readable, mostly ASCII |
| **ROT47** | ROT13's bigger cousin - rotates punctuation and digits too |
| **Reverse / flip text** | Backwards by character, word or line |
| **Tap / Polybius knock code** | Prisoner-of-war knock code — row taps, pause, column taps |
| **URL / percent encoding** | %20 and friends — making text safe inside a web address |
| **UUencode** | The Usenet ancestor of Base64 |
| **Unicode escapes** | é and \x41 — the way code writes awkward characters |
| **Unicode inspector** | Name every character — catches invisible and lookalike characters |
| **XXencode** | The uuencode cousin that survives systems uuencode couldn't |
| **Z85 (ZeroMQ Base85)** | ZeroMQ's Base85 - the variant safe to paste into source code |
| **basE91** | Denser than Base64 - squeezes more data into printable ASCII |

### Classical ciphers

| Tool | What it does |
|---|---|
| **ADFGX / ADFGVX** | German WWI field cipher — grid substitution plus column transposition |
| **Affine cipher** | Multiply then add: (a×letter + b) mod 26 |
| **Atbash** | Mirror the alphabet — A↔Z, B↔Y |
| **Bifid cipher** | Delastelle's fractionating cipher on a 5×5 keyed square |
| **Caesar / ROT-N shift** | Slide every letter N places along the alphabet |
| **Caesar brute force** | All 25 shifts at once, scored for how English they look |
| **Columnar transposition** | Write in rows under a keyword, read out in alphabetical key order |
| **Enigma machine** | The real rotor wirings, notches, plugboard and double-stepping |
| **Enigma solver** | Recovers rotor order, positions, rings and plugboard from ciphertext |
| **Four-square cipher** | Encrypts letter pairs across two keyed squares - stronger than Playfair |
| **Fractionated Morse** | Morse turned into groups of three, then substituted - a WWII field cipher |
| **Gronsfeld cipher** | Vigenère driven by a number instead of a keyword |
| **Hill cipher** | Matrix multiplication mod 26 - the first cipher on real linear algebra |
| **Nihilist cipher** | Polybius numbers plus a repeating numeric key - as used by 1880s revolutionaries |
| **One-time pad** | The only cipher proven unbreakable — and the hardest to use |
| **Playfair cipher** | Encrypts letter pairs in a 5×5 keyed grid — used in both world wars |
| **Polybius square** | Each letter as a row/column pair in a 5×5 grid |
| **Porta cipher** | Reciprocal polyalphabetic cipher - the same step encrypts and decrypts |
| **Rail fence cipher** | Write in a zig-zag across N rails, read off row by row |
| **Running-key cipher** | Vigenère where the key is a whole book passage |
| **Scytale** | The Spartan rod — wrap a strip round a stick of diameter N |
| **Simple substitution** | Your own 26-letter alphabet, or one built from a keyword |
| **Trifid cipher** | Bifid taken into three dimensions - a 3×3×3 keyed cube |
| **Vigenère cipher** | A Caesar shift per letter, driven by a repeating keyword |
| **Vigenère solver** | Works out the key length and the key from ciphertext alone |
| **XOR** | Exclusive-or against a repeating key — the CTF workhorse |
| **XOR key finder** | Recovers a repeating XOR key from ciphertext alone |

### Analysis

| Tool | What it does |
|---|---|
| **Compare two texts** | Where do these differ, byte by byte? |
| **Crib drag (XOR key reuse)** | Slides a guessed word along XOR'd data to find where it fits |
| **Entropy & randomness** | How random is this really? Shannon entropy per byte |
| **Frequency analysis** | Letter, bigram and trigram counts with a bar chart |
| **Hex dump / file inspector** | Offset, hex, ASCII — plus what the magic bytes say the file is |
| **Identify the cipher** | Reads the shape of ciphertext and suggests which cipher it is |
| **Kasiski examination** | Finds repeated sequences and the key lengths they imply |

### Encryption

| Tool | What it does |
|---|---|
| **Encrypt a file** | Password-encrypt any file to a .cryptex, and back again |
| **Encrypt a folder** | Zip a whole folder, then encrypt the zip |
| **Encrypt text with a password** | AES-256-GCM or ChaCha20-Poly1305, password-derived key |
| **Password & passphrase generator** | Cryptographically random passwords, with the strength worked out |
| **Password strength** | Estimate how strong a password is and how long it would take to crack |
| **Random bytes / keys** | Secure random data in whatever format you need |
| **Securely delete a file** | Overwrite then delete — with an honest word about SSDs |

### Hashing

| Tool | What it does |
|---|---|
| **Compare two files** | Are these two files byte-for-byte identical? |
| **Crack a hash (dictionary)** | Recover the text behind a plain hash using a wordlist and rules |
| **HMAC** | A hash with a shared secret mixed in — proves who sent it |
| **Hash a file** | Checksum a file on disk and optionally verify it |
| **Hash text** | Every common digest of whatever you paste in |
| **Password hashing (PBKDF2 / scrypt)** | Deliberately slow hashing — the right way to store a password |

### Keys & certificates

| Tool | What it does |
|---|---|
| **Encrypt with a public key (RSA)** | Anyone can lock it; only the private key opens it |
| **Generate a key pair** | Ed25519, RSA or ECDSA, as PEM — and OpenSSH if you want it |
| **Inspect a key or certificate** | What is this PEM? Type, size, subject, dates, fingerprint |
| **Self-signed certificate / CSR** | Make a test certificate, or a request to send to a CA |
| **Shared secret (Diffie-Hellman)** | Two people derive the same key without ever sending it |
| **Sign & verify** | Prove a message came from you and was not altered |

### Interop

| Tool | What it does |
|---|---|
| **Convert a key or certificate** | PEM to DER, pull out the public half, or write an OpenSSH key |
| **PKCS#12 (.pfx / .p12) bundle** | Package a key and certificate into a .pfx, or open one |
| **QR code** | Turn text into a QR code image (and read one back where possible) |
| **age encryption** | Encrypt and decrypt files the way the age tool does |
| **age key pair** | Make an age identity - a public 'age1...' and its secret key |

### Tokens & secrets

| Tool | What it does |
|---|---|
| **Authenticator codes (TOTP)** | Works out the six-digit code from a secret, at any point in time |
| **Check a checksum manifest** | Verifies a folder against a SHA256SUMS file |
| **Checksum manifest (SHA256SUMS)** | Hashes every file in a folder into one list you can check later |
| **JSON Web Token (JWT)** | Reads, checks and creates the tokens web logins run on |
| **New authenticator secret** | Makes a fresh TOTP secret and the set-up URI for it |
| **Split a secret into pieces** | Any three of five rebuild it; any two reveal nothing |

### Steganography

| Tool | What it does |
|---|---|
| **Bit-plane viewer** | Shows one bit of a picture on its own - where hidden data shows up |
| **Detect image steganography** | Chi-square and bit tests for whether an image is hiding LSB data |
| **Find files hidden inside files** | Spots data appended to, or buried inside, any file |
| **Hide a message in an image** | Writes text into the bottom bits of a picture's colours |
| **Hide a message in audio** | Writes text into the bottom bit of each WAV sample |
| **Hide text in whitespace** | Buries a message in the trailing spaces and tabs of ordinary text |
| **Hide text inside text** | Uses invisible Unicode characters to carry a message inside ordinary writing |
| **Image metadata** | Shows the camera, date and GPS position buried in a photograph - and removes them |
| **Read a message from an image** | Pulls a hidden message back out of a picture |
| **Read a message from audio** | Pulls a hidden message back out of a WAV |

### Signals

| Tool | What it does |
|---|---|
| **APRS packet generator** | Build a valid AX.25 frame and write it as audio |
| **DTMF (touch-tone) decoder** | Read the digits dialled in a recording |
| **DTMF (touch-tone) generator** | Turn a phone number or digit string into the touch-tones |
| **Listen and decode (live)** | Decode slow-scan pictures, touch-tones or Morse as they are heard |
| **Morse from audio** | Decode CW straight from a WAV recording |
| **PSK31** | Decode the narrow phase-shift mode used for keyboard-to-keyboard contacts |
| **PSK31 generator** | Turn text into a PSK31 audio file |
| **Packet radio / APRS (AX.25)** | Decode 1200 baud AFSK packets - callsigns, path and payload |
| **RTTY (radioteletype)** | Decode or generate 45.45 baud Baudot teleprinter signals |
| **RTTY generator** | Turn text into a RTTY audio file |
| **Slow-scan (SSTV) decoder** | Turn a recorded radio transmission back into the picture |
| **Slow-scan (SSTV) encoder** | Turn a picture into a transmittable WAV |
| **Spectrogram** | See the sound — and read anything hidden in it |

---

## Sound in: files, video, and live

Every signal tool takes **any audio or video file** - wav, mp3, m4a, aac, flac,
ogg, opus, mp4, mkv, mov, avi, webm. Plain PCM WAV is read directly; anything
else is converted first with the ffmpeg that ships inside the
`imageio-ffmpeg` package, so there is nothing to install separately and nothing
to configure. A phone video of a radio's speaker decodes as readily as a clean
off-air recording.

**Listen and decode (live)** does the same job on sound as it arrives. Pick what
to decode - slow-scan, touch-tones or Morse - press Start, and watch it build:

- An SSTV picture **paints itself line by line**, so within about fifteen
  seconds you know whether you have a usable signal or whether it is not worth
  waiting four minutes. Each finished picture is saved automatically, with the
  date, time and mode in the filename, and the decoder goes straight back to
  listening for the next one.
- Morse and touch-tones append as they are heard, with the tone frequency and
  the sending speed shown as it locks on.
- A level meter runs in the status bar the whole time, so "nothing is
  happening" and "nothing is arriving" are never confused.

### Getting the sound in

| Source | How |
|---|---|
| A radio | A cable from the headphone or data socket into line-in or a USB sound card. A phone speaker next to the laptop microphone genuinely works for a strong signal. |
| Whatever the computer is playing | **Windows:** pick one of the `[loopback]` devices at the bottom of the device list - WASAPI hands back the output stream directly, no cabling. **macOS:** install [BlackHole](https://existential.audio/blackhole/) or Loopback; it then appears as an ordinary input here. |
| A file or video you already have | Set *Sound from* to **A file, played through**. Leave *real time* on to watch it at natural speed, or turn it off to run through it as fast as the machine can manage. |

The live decoders run at roughly **200-300x real time** on a normal laptop, so
keeping up with a sound card is not remotely a problem, and a two-minute
recording runs through in well under a second with real time turned off.

### How the live decoder differs from the file one

The file decoder takes the whole recording and does one large FFT to recover the
tone's frequency. That is not available to a live decoder, because most of the
signal has not arrived yet. The live path instead uses a **streaming
discriminator**: the audio is mixed down against an oscillator at 1900 Hz,
low-passed, and the phase change from one sample to the next is taken - which
*is* the frequency deviation. Oscillator phase, filter history and last sample
all carry from block to block, so the output is continuous across block
boundaries with no seam. It is accurate to a fraction of a hertz on a clean
tone.

From there the same line-sampling and colour-assembly code runs as in the file
decoder, one line at a time, with sync pulses located and the line duration
re-fitted as the transmission goes on - so the slant correction gets *better*
the longer you listen.

Morse is handled the same way in both directions: the file decoder now runs the
streaming engine too, because it is the better of the two. It works the dot
length out from the keying itself by splitting marks into two clusters at the
geometric mean, re-reads the whole live window whenever that estimate improves,
and so corrects its own early guesses as more of the message arrives. It copes
with hand-sent timing jitter and gets call signs - mostly dashes, which defeats
a naive threshold - right.

### macOS and Windows notes

- **macOS** asks for microphone permission the first time you press Start. The
  build script declares `NSMicrophoneUsageDescription` in the app bundle, which
  is what makes that prompt appear rather than the app silently receiving
  silence.
- **Windows** needs no setup for a microphone or line-in. Loopback devices
  require Windows 10 or later.
- If `sounddevice` cannot find a sound system at all, the file-played-through
  path still works; the tool says so rather than failing silently.

---

## The slow-scan decoder, in more detail

Slow-scan television (SSTV) is how amateur radio operators send still pictures
over a voice channel. The transmitter sweeps an audio tone between 1500 Hz
(black) and 2300 Hz (white), one pixel at a time, with a 1200 Hz pulse at the
start of every line to keep the receiver in step. A picture takes one to four
minutes, hence the name.

Point **Slow-scan (SSTV) decoder** at a WAV recording and it will:

1. **Demodulate** the audio — recover the instantaneous frequency of every
   sample, which *is* the pixel value.
2. **Read the VIS header**, the digital preamble that says which mode was used,
   and check its parity bit.
3. **Find every sync pulse**, then fit a straight line through them. This is
   what removes the slant you get when the sound card's clock is slightly off
   from the transmitter's — the decoder measures the real line duration rather
   than trusting the nominal one, and reports both.
4. **Sample each scan line** at the right instants and assemble the colour
   planes for that mode's colour scheme (GBR for Martin and Scottie, YCbCr for
   Robot and PD, with the PD family carrying two picture rows per transmitted
   line).

Nineteen modes: **Martin M1, M2, M3, M4 · Scottie S1, S2, S3, S4, DX ·
Wraase SC2-180 · Robot 36, 72 · PD50, PD90, PD120, PD160, PD180, PD240, PD290.**
That covers essentially everything you will meet on the air, including Robot 36,
which is what the ISS uses for its picture downlinks on 145.800 MHz, and PD290,
which at 800 x 616 is the largest picture in common use and takes nearly five
minutes to send.

If the header is missing or corrupt — common on a weak signal — set the mode by
hand and nudge the start offset until the picture squares up.

The **encoder** does the reverse, so you can check the whole path: take a
picture, make a WAV, decode it back. The self-test does exactly that for all
nineteen modes and fails the build if any of them comes back wrong.

Any audio or video file works - see **Sound in** above - and
**Listen and decode (live)** runs the same decoder on sound as it arrives.

---

## The other radio modes

Three more digital modes, all of which read any audio or video file and all of
which will also write one, so each can be tested against itself.

**RTTY** is the oldest of them and sounds like a warbling two-note chirp. The
transmitter hops between a mark and a space tone - 170 Hz apart at 45.45 baud
for amateurs - and underneath is Baudot, five bits per character with shift
codes to swap between letters and figures. Cryptex finds the two tones in the
spectrum for you, recovers the symbol clock from the signal's own transitions,
and **tries both polarities**, because mark and space the wrong way round is
the single commonest reason RTTY decodes as rubbish and it is worth not having
to guess. Commercial and weather circuits use 425 and 850 Hz shifts; set them
by hand if 170 fails.

**PSK31** does not move the tone at all. It keeps one steady note and flips its
phase by half a turn to send a zero, at 31.25 baud, with the amplitude eased to
nothing through every reversal so the whole signal fits in about 60 Hz - which
is why it gets through when nothing else will. Finding the carrier accurately
matters enormously at that width, so Cryptex **squares the signal first**: a
half-turn phase flip becomes a whole turn and cancels, leaving a clean tone at
twice the carrier that can be located to a fraction of a hertz. Any residual
tuning error then shows up as a constant twist on every symbol and is measured
and undone; the figure is reported, so you can see how far off you were.

The character set is varicode, and it is a lovely piece of design: no character
contains two zeros in a row, which leaves `00` free to mean *end of character*
and does away with start and stop bits altogether. Common letters get short
codes - `e` is a single bit.

**AX.25 packet** is the short harsh buzz you hear on 144.800, and unlike the
other two it is a real network protocol. Every frame carries who sent it, who
it is for, the digipeater path, a payload and a CRC, so you can tell whether
what you decoded is right rather than hoping. The signalling is Bell 202 -
1200 and 2200 Hz at 1200 baud, exactly as telephone modems worked in the
seventies - with HDLC framing on top: `01111110` marks the edges of a frame and
a zero is stuffed after any five ones so that pattern can never occur inside
one. APRS payloads are read far enough to say what they mean, so a position
report comes back as a latitude and longitude rather than a row of digits.

All three decode cleanly down to around 6 dB signal-to-noise in testing, and
the self-test checks exactly that rather than only the clean case.

---

## Enigma

A complete Enigma machine and a solver for it.

The wirings are the real ones - rotors I to VIII with their historically
correct turnover notches, reflectors B and C, the thin reflectors and the Beta
and Gamma fourth rotors of the naval M4, and a full thirteen-cable plugboard.
The double-stepping is there too: the middle rotor advances both when the right
rotor passes its notch *and* when it is sitting on its own, which is the quirk
every half-implementation gets wrong. It reproduces the published test vectors
exactly.

Two properties fall out of the wiring, and both matter. Because the reflector
sends the current back through, **encryption is its own inverse** - the same
settings turn plaintext into ciphertext and back, which is why there is one
button rather than two. And because the reflector never joins a letter to
itself, **no letter can ever encrypt to itself**. That is the flaw that made
cribs work at Bletchley, and it is what the solver uses.

### What the solver can and cannot do

Being honest about this is more useful than a confident number.

With **no plugboard**, it will find the rotor order, the window positions and
the ring settings from a couple of hundred letters unaided: every ordering
against all 17,576 positions, each decryption scored on four-letter English
statistics, then a ring sweep, then cables added one at a time - always the one
that improves the score most, which is Turing's own hill-climb.

With **cables in**, ciphertext alone is not enough at this length and no amount
of cleverness in the search fixes that - the true setting still scores higher
than the rest, but by so little that it sits somewhere in the top few hundred
rather than first. That is not a defect in the implementation; it is why the
bombes existed.

So give it a **crib**: a word or phrase you expect, ideally at the opening. The
no-self-encryption rule alone throws out more than half the places it could
sit. The rest are swept, and a setting is judged by how many of the crib's
letters come out right *with no plugboard at all* - cables spoil some of them,
but a letter is left alone unless a cable happens to catch it, so the true
setting shows a run of hits where a wrong one shows almost none. The cables are
then chosen to make the rest of the crib come out right.

If you also know the **ring settings** - often you do; they were a daily
setting shared across a net - it recovers everything exactly, through five or
six cables, in about twenty seconds. A sixteen-letter crib handles three
cables; a twenty-letter crib handles five.

When it fails it says so, rather than presenting its best guess as an answer.

---

## Steganography

Encryption makes a message unreadable. Steganography makes it unnoticed. They
are not rivals - the sensible thing is to encrypt first and hide second, so
that finding the hiding place still leaves nothing.

**In pictures.** Every pixel is three numbers from 0 to 255, and changing the
last bit of one moves it by a step out of 256: invisible on a screen, invisible
in print, invisible beside the original. So the bottom bit of every colour
value is free storage, and a 12-megapixel photograph has about four and a half
megabytes of it. Give it a password and the message is encrypted with
AES-256-GCM before it goes in. The result is a PNG and has to stay one - JPEG
works by throwing away exactly the detail the message lives in, and so does
almost every chat app and social network on upload. Send the file, not the
picture.

**Finding other people's.** The bit-plane viewer pulls out one bit of the image
on its own. In a photograph the bottom bit is sensor noise and looks like grey
static; hidden data looks like static too, but *structure* there - blocks,
edges, a band of solid black partway down, readable text - means somebody has
been at it. In flat artwork or a screenshot the bottom bit is not noisy at all,
so structure proves nothing; the two randomness figures underneath tell you
which case you are in.

**In text.** Unicode has characters that take no space and draw nothing. Two of
them are enough to spell out bits, so a message can be written as a run of
nothing and dropped into an ordinary sentence, and it survives being pasted
into most chat apps and documents. It does not survive anything that normalises
or strips Unicode, and the character count will not match what is on screen, so
it is easy to spot if anyone thinks to look.

**In audio.** The same trick as pictures, in sound: a 16-bit audio sample is a
number from -32768 to 32767, and flipping its bottom bit shifts the level by one
part in 65,536 - below anything you can hear. A few minutes of CD-quality WAV
hides tens of kilobytes, encrypted first if you set a password. It has to stay a
WAV: MP3 and AAC discard exactly the inaudible detail the message lives in.

**In whitespace.** Every line of text can carry a few invisible bits after its
last visible character, as trailing spaces and tabs. It survives being pasted
into a lot of places the zero-width Unicode trick does not - but code editors set
to trim on save will wipe it, which is the trade-off.

**Detecting it.** The bit-plane viewer shows you the bottom bit; the detector
puts a number on it, running the classic chi-square "pairs of values" test that
LSB embedding gives away and reporting *likely*, *possible* or *clean*. It reads
the statistics; it does not extract.

**Carving.** Almost every format has an end marker and almost every program
stops there - a PNG at IEND, a JPEG at FFD9, a PDF at `%%EOF`. Anything written
after that point is still in the file and completely invisible to the viewer,
which is why `cat photo.png secret.zip > out.png` has worked for thirty years.
Cryptex checks for that first, then sweeps the whole file for the opening bytes
of around twenty formats, and will write out what it finds.

**Metadata.** A photograph carries the camera, the lens, the date and time to
the second, sometimes the body's serial number, and - if location was on - the
latitude and longitude to within a few metres. None of it is visible and all of
it travels with the file. Cryptex shows the lot and will write a copy with all
of it removed.

---

## Interop - talking to other software

Everything else that encrypts here uses Cryptex's own container, which is fine
when both ends run Cryptex and useless otherwise. The Interop tab speaks the
formats the rest of the world already understands.

**age** is the modern answer to "encrypt this file for one particular person" -
the job PGP used to do, stripped of its options. Make a key pair and you get a
one-line public recipient starting `age1` to hand out and a secret that never
leaves your machine; encrypt to someone's recipient and only their secret opens
it, or set a passphrase instead. What comes out is a real age file that the age
command-line tool and everything built on it will open, and it opens theirs.

**QR codes** move a key, a two-factor secret or a short message off the screen
and onto a phone without typing. Encode writes a PNG at the error-correction
level you choose; reading one back works where the system has the zbar library,
and says so plainly where it does not.

**Key and certificate conversion** moves a key between PEM and DER, pulls the
public half out of a private key or certificate, and writes the one-line OpenSSH
public form. And the PKCS#12 tool builds the password-protected `.pfx`/`.p12`
bundle of a key plus its certificate that Windows, macOS Keychain and browsers
expect - or opens one back into PEM.

---

## Tokens and split secrets

**Authenticator codes.** The six digits are not sent to you and are not random:
your phone and the server share one secret, both look at the clock, and both
compute the same answer from the number of thirty-second periods since 1970.
That is the whole algorithm, which is why it works in aeroplane mode. Paste a
base32 secret or the whole `otpauth://` URI from behind a set-up QR code and
Cryptex gives you the code, the previous and next ones - servers normally
accept a step either side for clock drift - and the code at any time you name.
It matches the published RFC 6238 test vectors, which the self-test checks.

**JWTs.** Three base64 pieces joined by dots, behind most `Authorization:
Bearer` headers. The thing people get wrong is that a JWT is **signed, not
encrypted** - anyone holding one can read every claim in it, so nothing private
belongs inside. Cryptex decodes it, lays out the claims, says in words when it
was issued and when it expires, checks the signature against a shared secret or
a PEM public key, and flags the classic hole: a token whose algorithm is
`none`, which a server that trusts the header to tell it how to verify will
happily accept.

**Shamir's Secret Sharing.** Cutting a password into five chunks is a bad idea:
each chunk gives away a fifth of it and you need every one back. Shamir's
scheme does it properly. Two points define a line, three define a parabola - so
hide the secret as the constant term of a curve of degree two, hand out five
points on it, and any three determine it exactly while any two fit infinitely
many curves equally well and say nothing at all. Not *hard to break*;
impossible, in the same way as a one-time pad. Good for a master password left
with family, or a wallet seed split across locations.

**Checksum manifests.** One line per file: hash, two spaces, name. The same
`SHA256SUMS` format that ships beside Linux images, readable by `sha256sum -c`
anywhere. Make one when a folder is known good and checking it later tells you
exactly what has changed, what has gone and what has appeared since - which
catches silent disk corruption as readily as tampering, and in practice that is
the more common of the two.


---

## Python version notes

Built and tested on Python 3.9 through **3.14**. Two things that bite apps on
newer Pythons are handled:

- The `uu` module was deprecated in 3.11 and **removed in 3.13**, so uuencoding
  is done here directly with `binascii` — which also made the decoder tolerant
  of the trailing spaces mail systems strip and of a missing `begin` line.
- `datetime.utcfromtimestamp` is deprecated from 3.12; timezone-aware calls are
  used instead.

Nothing else in the app touches a module removed in 3.12, 3.13 or 3.14.

The self-test is what catches this class of problem, which is why the build
scripts run it on the finished executable and refuse to report success if
anything fails.

---

## Things worth knowing

**The classical ciphers are not security.** Every one of them is broken, several
of them by tools in this same app — Caesar brute force tries all 25 shifts and
ranks them, the Vigenère solver recovers the key length and the key from
ciphertext alone, the XOR key finder does the same for repeating-key XOR. They
are here to learn from, to solve puzzles with, and to recognise. The app says so
on each one rather than leaving you to guess.

**The encryption is.** AES-256-GCM and ChaCha20-Poly1305, both authenticated, so
a tampered ciphertext fails loudly instead of decrypting to something wrong.
Keys come from your password through Argon2id, scrypt or PBKDF2 with a random
salt. Nonces are generated fresh every time and are never yours to choose,
because reusing one is the single thing that breaks GCM completely.

**There is no recovery.** Lose the password and the data is gone. That is what
makes it work.

**File encryption is chunked.** 1 MB at a time, each chunk separately
authenticated and numbered, so size is no object and nobody can reorder, drop or
splice chunks without decryption failing. The original file name is stored
inside the encrypted file, so decrypting restores it even if the `.cryptex` was
renamed. Your original is never deleted — delete it yourself once you have
confirmed the encrypted copy opens.

**Folders are zipped, then encrypted**, rather than encrypted file by file. That
hides the file names as well as the contents.

**Secure delete is honest about SSDs.** Overwriting works on a mechanical hard
drive. On flash storage wear levelling means the drive writes your overwrite
somewhere else entirely, and the original blocks sit there until it feels like
reusing them. The tool says so instead of pretending.

---

## Auto-solve

The one to reach for when you have no idea. Paste anything, press **Solve it**,
and Cryptex tries everything it reasonably can, in every order it reasonably
can, and ranks what comes out.

It works in **layers**, because real puzzles are layered. At each step it tries
the decoders whose shape matches what it is holding, then feeds each result
back in and tries again:

> Base64 → Decompress (gzip) → *"Meet me at the old mill at nine tonight"*

Alongside the decoders it sweeps the key spaces small enough to sweep — all 25
Caesar shifts, all 312 affine keys, Atbash, ROT47, rail fences to twelve rails,
scytale to twenty-four, all 255 single-byte XOR keys — plus the statistical
solvers for repeating-key XOR and Vigenère. Tick **thorough** and it will also
hill-climb a full 26-letter substitution key, which needs a paragraph or so of
text to have anything to work with.

That hill-climb, and the Enigma solver, are both driven by **quadgram
fitness**: the log-probability of every four-letter run in the text, measured
against English. Words are the better judge of a finished answer, but they are
useless halfway through a climb - a key that is eighty per cent right produces
no whole words at all, while its quadgrams are already measurably better than
its neighbours'. That gradient is what lets a hill-climb find its way, and it
is mixed into the general readability score as well, where it settles the cases
word-counting cannot.

Each answer comes with the **exact recipe**, so you can repeat it by hand in the
individual tools, and a confidence figure.

### How it decides what is an answer

Everything that comes out is scored by one shared measure, which is the part
that actually makes this work. Most of it is **English words counted by the
letters they cover**, not by how many words match — otherwise a scatter of accidental
two-letter hits carries a line of nonsense to a respectable score. When the
spaces are missing, as they are after a classical cipher, it reads the letters
as run-together words instead, so `ATTACKATDAWNBRINGTHEMAPS` is recognised for
what it is. Recognisable structure counts too — but JSON is confirmed by
actually parsing it, because plenty of cipher output starts with `[` and ends
with `]`, and treating that as a solved puzzle sends the whole search off a
cliff.

On a few hundred random letters the measure averages **0.13**; real plaintext
scores **0.54 to 0.74**; JSON or a PEM block scores **0.97**. That gap is the
whole game.

### How it decides what to try next

A Base64 decode that succeeds is a **fact** — the data really was Base64. An
affine decode with a guessed key is a **guess**, and a wrong guess produces
letters with much the same statistics as a right one. So every step carries a
weight, the weights multiply along a chain, and the search follows the chain
with the most fact in it first. Without that distinction it happily follows
whichever noise scores a fraction higher and never reaches the answer.

Two more things keep it honest:

- It **stops early** when it has an answer, so the common cases return in well
  under a second rather than burning the whole time limit.
- It **refuses to invent an answer**. Give it something properly encrypted and
  it says so and points you at Entropy & randomness, rather than dressing up
  the best of a bad set of guesses as a solution.

The self-test builds twenty layered puzzles — Base64 of a Caesar shift, a
reversed ROT13, URL of Base64 of hex, Base64 of XOR of gzip, Base32 of Base64,
a Vigenère, a rail fence, a scytale — solves every one, and checks that
properly encrypted data is refused. The build fails if any of that stops being
true.

---

## What it recognises

Paste anything into any tool and the bar under the input says what it appears
to be, how sure it is, and why — with one button that switches to the right
tool and takes your text with it, and another that hands it to Auto-solve.

It knows the shape of: Base64 (standard and URL-safe), Base32, Base58, Base62,
Base16/hex, Base85, binary, decimal and octal bytes, A1Z26, ROT47, Morse,
Bacon, tap code, Polybius, ADFGVX, URL and HTML escapes, Unicode escapes,
quoted-printable, punycode, uuencode, JWTs, PEM blocks and OpenSSH keys, hash
digests by length, bcrypt/Argon2/scrypt/PBKDF2 password hashes, UUIDs, Unix
timestamps, JSON and XML — and the statistical fingerprints that separate a
substitution cipher from a Vigenère from plain English.

It also spots the newer things: an `otpauth://` set-up URI, a set of Shamir
shares and how many of them you need, a SHA256SUMS manifest, an APRS frame
written out as `CALL>DEST:payload`, ciphertext in five-letter groups (which is
the shape of Enigma traffic) — and **text with invisible characters in it**,
which it will tell you about with a rough count of how many bytes are hiding
there.

It also looks **one layer deeper**: it will tell you a string is *Base64 of
gzip-compressed data*, or *Base64 of a PNG image*, by decoding the outer layer
and reading what is underneath — and sends you straight to Auto-solve when
there is more than one layer to peel.

And it knows when to stay quiet. Paste ordinary English and it says so rather
than insisting everything is a cipher.


---

## Made to be used without reading the manual

**It tells you what you are holding.** Paste anything into the input box and a
bar underneath says what it appears to be and how sure it is — *"This looks like
Base64 of gzip-compressed data (98% sure)"* — with one button that switches to
the right tool and takes your text with it, and an **Auto-solve** button that
hands it straight to the solver. It updates as you type, never changes your
input, and stays quiet when what you pasted is just ordinary English.

**Settings guess for you.** Anywhere a tool would otherwise ask what format
something is in, the default is **auto**: XOR works out whether the input and
the key are text, hex or Base64 and tells you what it assumed; HMAC does the
same with the key; the XOR key finder reads hex or Base64 without being told;
the SSTV decoder reads the mode from the transmission; the live listener uses
the sound card's own sample rate. You can always override it, and the result
says what it decided.

**Settings that do not apply are hidden.** Pick *Morse* in the live listener and
the SSTV mode and picture folder disappear; pick a file instead of a microphone
and the device list is replaced by a file box. Leave the SSTV mode on auto and
the manual start-offset control stays out of the way. The panel never shows you
a control that cannot do anything.

**Pick a file and it tells you what it is** — size, type from the magic bytes,
and for audio and video the duration and codec, before you press anything.

**Every tool explains itself** in plain English: what it does, when you would
use it, a worked example, and an amber caution line where one is warranted
(*"Historical cipher — trivially broken. Never use it to protect anything
real."*). Fold the panel away from **View** once you no longer need it.

**Dark by default**, with light a keystroke away (Ctrl+D, or the button top
right). In both themes anything you can type in or click sits on a different
shade from the surface behind it, carries a real border, and gets an accent
ring when it has focus — so an input never has to be hunted for.

---

## Tips

- **Start with "What is this?"** when you do not know what you have, or just
  paste into any tool and read the detection bar.
- **Chain tools.** Decoded output that is still encoded? Press **Send output to
  the input box** and pick the next tool — or click the suggestion in the
  detection bar, which carries the text across for you. Layered
  Base64-inside-hex-inside-URL is common and takes three clicks.
- **Search.** Ctrl+F, then type anything — "totp", "wav", "bitcoin", "ssh",
  "webhook". The search covers names, summaries, tags and explanations.
- **Every tool explains itself.** The "How this works" panel is the point of the
  app as much as the tools are. Turn it off in View when you no longer need it.
- **F5** runs the current tool's main action (Start / Stop on the live
  listener). **Ctrl+D** switches dark and light. **Ctrl+Enter** sends the output
  back to the input.
- **Everything saves to Downloads** - saved output, encrypted files, pictures,
  WAVs - unless you choose another folder under **File > Default save folder…**
  (Reset to Downloads sits beside it). Every "Save into" box starts out pointing
  there; clear it to write beside the source file instead, where there is one.

---

## Files

```
cryptex.py            run from source (also: python cryptex.py selftest)
cryptex_app.py        frozen entry point (crash log, selftest mode, Finder -psn)
build-exe.bat         Windows build          build-app.command   macOS build
ensure_python.ps1     Windows: find or install a real Python
run.bat / run.command from-source launchers
requirements.txt      cryptography, pillow, numpy, argon2-cffi,
                      imageio-ffmpeg (bundled ffmpeg), sounddevice (live audio)
cryptexlib/
  core.py             the Tool/Param/Result registry everything else plugs into
  ui.py               the window - built entirely from the registry
  theme.py            light and dark palettes
  registry.py         imports every tool module (the only wiring there is)
  identify.py         "what is this?"
  encodings.py        Base-N, web encodings, Morse, Braille, Baudot, Bacon, tap
  classical.py        historical ciphers, plus the solvers that break them
  modern.py           AES-GCM / ChaCha20 text, file and folder encryption
  hashing.py          digests, HMAC, password hashing, file verification
  keys.py             key pairs, signatures, RSA, certificates, Diffie-Hellman
  language.py         the English model everything ranks candidates by
  solver.py           auto-solve: the transform set and the best-first search
  audio.py            any-file-to-PCM via ffmpeg, sound devices, streaming FM demod
  signals.py          SSTV decode/encode, DTMF, Morse from audio, spectrogram
  live.py             streaming decoders and the live listening tool
  analysis.py         frequency, entropy, Kasiski, hex dump, compare, crib drag, cipher id
  classical_extra.py  Porta, Gronsfeld, Bifid, Trifid, four-square, Nihilist, Hill, frac. Morse
  interop.py          age, QR codes, key/cert conversion, PKCS#12
  enigma.py           the machine, the fast integer core, and the solver
  radio.py            RTTY, PSK31 and AX.25 packet - decode and generate
  stego.py            LSB images, bit planes, zero-width text, carving, EXIF
  tokens.py           TOTP, JWT, Shamir's Secret Sharing, checksum manifests
  selftest.py         runs everything and reports what fails
```

## Adding a tool

One function and one `tool(...)` block; the interface builds itself from the
declaration. Nothing in `ui.py` knows what any individual tool does.

```python
from .core import Param, tool, to_text

tool(id="shout", name="Shout", category="Encodings",
     summary="Make it louder",
     explain="Puts the text in capitals and adds an exclamation mark.",
     params=[Param("marks", "Exclamation marks", "int", 1)],
     encode=lambda d, marks=1: to_text(d).upper() + "!" * int(marks),
     decode=lambda d, **k: to_text(d).rstrip("!").capitalize())
```

Add the module to `cryptexlib/registry.py` if it is a new file, and a line in
`selftest.py`'s `CASES` if the round trip needs particular settings.

---

*Cryptex 1.4 — built for Dan Lowther, September 2026.*
