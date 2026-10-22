# ARAP desktop client

The desktop client is a local Tk application with key creation, generic content and PixelQSO card signing/verification, local trust management, one-time challenge issue/respond/verify, LoTW enrollment-record management, and proof/key publishing or retrieval. The Keys & Trust tab can issue a verifier-side LoTW enrollment challenge, sign a response through the optional `arap-tqsl-sign` helper built against TrustedQSL source, and verify a signed response using local TQSL ARRL roots by default; a PEM override is optional. The helper keeps the TQSL private key inside TQSLLIB and does not submit QSOs. TQSL-supported RSA/SHA-1 is accepted only for enrollment assertions; ARAP content and challenge signatures remain Ed25519. The app explains enrollment signing and asks before it signs or queries live certificate status.

Requirements: Python 3 with Tk 8.6 and a built `arap` executable. Run from the repository root:

```sh
make desktop
```

Or build separately and launch with Python:

```sh
make build
python3 desktop/arap_desktop.py
```

Select the executable at the top if it is not found on `PATH`. The app does not start a listener, save the upload token, or change trust unless you choose those actions.

Key generation writes a passphrase-encrypted Ed25519 private key in the standard armored age file format and a separate public-key PEM. Use an `.age` suffix for the private key. It writes age's scrypt work factor 15 and accepts factors through 18 when loading a key; use at least 12 UTF-8 bytes for the passphrase. New files are owner-only where supported, and existing files are never overwritten. Signing prompts for the key passphrase without placing it in command arguments or environment variables. Legacy unencrypted PKCS#8 keys remain readable; on Unix, ARAP refuses private-key files readable by group or other users. ARAP does not use an OS keychain. Publishing sends only public-key or proof files.

`make package` creates a platform-specific ZIP in `dist/` with the CLI, keyserver, desktop client, launcher and profile documentation. Set `TARGET=linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`, or `windows-amd64` to cross-build a target. The launcher bundle still requires Python 3 and Tk 8.6; the desktop client discovers its adjacent CLI automatically. The CI workflow builds seven-day review bundles for those targets.
