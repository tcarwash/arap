# ARAP 0.1.0 beta

This beta provides Ed25519 content proofs and challenge authentication, optional
TQSL Callsign Certificate enrollment, PixelQSO card proofs, key endorsements,
and an optional self-hosted proof/key reference service. It is intended for
evaluation by application developers and radio operators.

TQSL's RSA/SHA-1 signature is used only for the short-lived enrollment
assertion. ARAP content and challenge signatures remain Ed25519. A Callsign
Certificate and its current status are authentication evidence under ARAP
policy; ARAP enrollment is not an ARRL-approved login, endorsement, or LoTW
authentication mechanism. Real-certificate and live-status validation must be
completed separately before relying on enrollment in production.

Native enrollment bundles target Linux amd64/arm64, macOS amd64/arm64 and
Windows amd64. Each release candidate is assembled only from successful native
CI artifacts for its tag. See the included `FIRST-RUN.md` and dependency notices
before use.
