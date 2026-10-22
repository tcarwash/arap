# ARAP beta first run

ARAP is a local signing and authentication toolkit. Its libraries and Python
wrapper let an application carry signed content and challenge messages over its
own transport. The desktop and bundled CLI are reference clients; they do not
create an ARAP account or provide an authentication server.

## Start and check the installation

1. Extract the archive to a folder you can write to.
2. Start `arap-desktop.sh` on Linux/macOS or `arap-desktop.bat` on Windows.
   Python 3 with Tk 8.6 is required. Select **Setup diagnostics** in the window
   if the CLI, TQSL helper, or standard TQSL data directory is not detected.
3. Open **About** and record the ARAP version and source commit when reporting
   an issue. The Linux amd64 archive also reports its pinned TQSL/TQSLLIB version.
4. Try the signing and challenge workflows with test keys and files before
   connecting another application. Keep the private key with its owner; exchange
   only public keys, challenge requests/responses, and proof files.

## Try the application flows

- **Sign and verify content:** create an encrypted ARAP key in **Keys & Trust**.
  Add the public key to a local trust store for `content-signature`, sign a test
  file, and verify the detached proof against the original file and expected
  context. Changing one byte should make verification fail.
- **Authenticate a peer:** use **Challenge** to issue a short-lived request,
  send the request file to the responder through your chosen transport, and
  have the responder produce a response with its key. Verify and consume that
  response once. Keep the verifier's challenge database durable; replay must
  fail. Mutual authentication requires both inverse requests to be bound to
  the same application session.
- **Use TQSL enrollment:** native enrollment bundles target Linux amd64/arm64,
  macOS amd64/arm64 and Windows amd64; check release validation for the
  hosted native results.
  Import and verify a current Callsign Certificate in TQSL first. Issue
  a fresh enrollment challenge for the intended audience and ARAP key. On the
  responder, list matching certificate serials, choose the intended serial, and
  review the signature notice and confirm before signing this
  enrollment assertion. ARAP's content and challenge signatures remain Ed25519. The
  verifier separately checks its certificate roots and current status service. This is experimental
  authentication evidence for ARAP; it is not an ARRL-approved login, QSO
  submission, or LoTW transaction. Do not select a real content-signing purpose
  until the verifier has reviewed its policy. The checked integration versions
  are TQSLLIB 2.8.7 and TQSL 2.8.7-rc5; other TQSL releases are not yet
  qualified. The enrollment binding view shows certificate expiry and status
  evidence age. Refresh is explicit and requires the previously accepted
  response file; it cannot re-enable a disabled binding.

The source checkout includes deterministic offline demonstrations. With Go,
Python, CMake, OpenSSL/SQLite/Expat/zlib development packages and the pinned
TrustedQSL source available, run `make signing-demo` and `make enrollment-demo`.
The enrollment demo creates a synthetic CA and TQSL data directory, uses only
synthetic credentials, and injects synthetic status in its verifier. It proves
the test flow, not a live LoTW result.

## If something fails

Use **Setup diagnostics** to copy the relevant installation details into a bug
report. For a missing CLI, choose the adjacent `arap` executable with the
header's **Browse…** control. For missing TQSL enrollment support, check that
you have the Linux amd64 archive, its helper and resource file, a supported
TQSL installation, and certificate data in TQSL's normal user directory. A
wrong certificate password, callsign mismatch, stale certificate, or incorrect
serial must be corrected in TQSL or the enrollment form; ARAP never exports the
station private key. Do not attach private keys, passwords, certificates,
trust databases, enrollment databases, unredacted logs, or real QSO records to
an issue.
