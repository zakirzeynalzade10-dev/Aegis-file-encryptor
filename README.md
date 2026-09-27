# AEGIS CRYPT

Military-styled AES-256 file encryption, usable as a desktop GUI **and** a
command-line tool from the same codebase.

## What's inside

| File            | Purpose                                                        |
|-----------------|-----------------------------------------------------------------|
| `aegis_core.py` | The encryption engine. All crypto logic lives here.            |
| `aegis_cli.py`  | Command-line interface.                                         |
| `aegis_gui.py`  | Desktop GUI (pure `tkinter` — no extra install needed).         |
| `aegis.py`      | Single entry point: no args → GUI, args → CLI.                  |
| `test_core.py`  | Automated tests for the encryption engine.                       |
| `requirements.txt` | The one third-party dependency (`cryptography`).             |

## Install

```bash
pip install -r requirements.txt
```

That's it. The GUI uses `tkinter`, which ships with the standard Python
installer on Windows and macOS. On some minimal Linux distributions you may
need `sudo apt install python3-tk` (Debian/Ubuntu) or your distro's
equivalent package.

## Run

```bash
# Desktop app
python aegis.py

# CLI
python aegis.py encrypt -i secret.pdf
python aegis.py decrypt -i secret.pdf.axc
python aegis.py encrypt -i "C:\Documents\Project" -r   # whole folder, recursive
python aegis.py info -i secret.pdf.axc                  # inspect without decrypting
```

Run `python aegis.py encrypt --help` for every flag (custom output path,
`--force` to overwrite, `--delete-original`, `--password-file` for
scripting, `--chunk-size`, etc.).

## Security design

- **Cipher:** AES-256 in GCM mode (authenticated encryption — confidentiality
  and integrity together) via the well-audited `cryptography` library's
  OpenSSL bindings. No hand-rolled AES.
- **Key derivation:** `scrypt` (memory-hard), so brute-forcing a passphrase
  is expensive even with GPUs/ASICs, unlike a fast hash.
- **Per-chunk nonces:** files are processed in chunks (default 1 MiB), each
  with its own randomly generated 96-bit nonce, so encrypting huge files
  never risks nonce reuse under the same key.
- **Tamper/truncation detection:** each chunk's position and "is this the
  last chunk" flag are cryptographically bound into the authentication tag.
  An attacker cannot truncate, reorder, or splice chunks — including
  silently dropping the real final chunk — without decryption failing.
- **Atomic writes:** output is written to a temporary file and only renamed
  into place on success, so a crash or interrupted run never leaves a
  half-written, corrupted-looking output file overwriting your original.
- **No plaintext passwords on the command line:** the CLI prompts
  interactively (hidden input) or reads from a file you control; passwords
  are never accepted as a bare CLI argument, which would otherwise leak into
  shell history and process listings.

This is a solid, defensible design for real-world file protection. It has
**not** been through third-party security audit or formal certification —
if you're shipping this commercially, get an independent cryptography
review before making strong security claims to customers, especially in
regulated markets (finance, healthcare, government).

## Turning this into a sellable product

A few concrete next steps once you're happy with functionality:

1. **Package as a native executable** with [PyInstaller](https://pyinstaller.org/)
   so customers don't need Python installed:
   ```bash
   pip install pyinstaller
   pyinstaller --onefile --windowed --name "AegisCrypt" --icon=your_icon.ico aegis.py
   ```
   `--windowed` suppresses the console for the GUI; drop it if you want a
   console build for CLI-only distribution instead, or ship both.
2. **Code-sign the executable** (Windows: Authenticode certificate; macOS:
   Apple Developer ID + notarization) — unsigned .exe/.app files trigger
   scary OS warnings that kill conversion for a paid product.
3. **Versioned file format:** the container header already reserves fields
   for future scrypt parameter upgrades, so you can strengthen defaults
   later without breaking old files.
4. **Licensing/activation, auto-update, and installer (Inno Setup on
   Windows, a signed .pkg on macOS)** are business-layer concerns outside
   this codebase's scope — straightforward to add on top once the core
   product is validated.
5. **Get a real audit.** For anything sold on a security promise, an
   independent cryptography review is what lets you make that promise
   credibly.

## Running the tests

```bash
python test_core.py
```
