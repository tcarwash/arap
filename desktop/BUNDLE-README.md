# ARAP desktop bundle

This bundle contains the ARAP command-line client and keyserver plus the Tk desktop app. Python 3 and Tk 8.6 are required to run the desktop app.

Native enrollment bundles include the TQSL helper, pinned TQSLLIB
runtime resources and its `config.xml` (TrustedQSL 2.8.7 source revision
`1916fc14a8cfc7f287742ae5a34aa986353d9df7`). The helper requires the standard
platform runtime libraries for OpenSSL 3, SQLite, Expat, zlib, zstd, and the C++ runtime. A compatible
TQSL installation and an existing Callsign Certificate are needed to perform
real enrollment. Enrollment integration was exercised with pinned TQSLLIB 2.8.7
and a local TQSL 2.8.7-rc5 installation; other TQSL releases are not yet
qualified. The helper uses TQSL's supported RSA-SHA1 API only for the fresh
enrollment assertion that binds the station certificate to an ARAP key. ARAP
content and challenge signatures use Ed25519. The assertion is authentication
evidence for ARAP; it is not an ARRL-approved login or LoTW transaction.

The native enrollment build matrix targets Linux amd64/arm64, macOS amd64/arm64
and Windows amd64. Check the release notes for which native builds have passed
hosted validation.

## Start the desktop app

- Linux or macOS: run `./arap-desktop.sh`.
- Windows: run `arap-desktop.bat`.

The desktop app finds the adjacent `arap` executable automatically. You can also launch it with `python3 arap_desktop.py` (or `py -3 arap_desktop.py` on Windows).

The `arap` command-line client is available directly. The `arap-keyserver` program is an optional local service; configure `ARAP_DATA_DIR` and `ARAP_UPLOAD_TOKEN` before starting it:

```sh
ARAP_UPLOAD_TOKEN='choose-a-long-random-token' ./arap-keyserver
```

This evaluation bundle does not include private keys, trust stores, challenge databases, uploaded objects, or server tokens. Keep those as your own local files.

Read `FIRST-RUN.md` for the content-signing and challenge walkthrough and the
experimental TQSL enrollment boundary. Use `BUG_REPORT_TEMPLATE.md` when
reporting a problem; include sanitized diagnostics only.
