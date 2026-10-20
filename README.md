# ARAP — Amateur Radio Authentication Profile

**Status: design scaffold / draft specification, no implementation yet.**

This project proposes a transport-independent way to sign amateur-radio content and station authentication exchanges using existing standards. It is particularly intended to support signed PixelQSO cards, arbitrary messages, and optionally short voice/CW references to full hosted proofs.

Start with [`spec/ARAP-v0.1.md`](spec/ARAP-v0.1.md). Supporting notes live in [`docs/`](docs/).

## Install the scaffold locally

From the downloadable archive, unpack into `/home/tyler/dev/arap`:

```bash
mkdir -p /home/tyler/dev/arap
unzip arap-project.zip -d /home/tyler/dev/arap
```

(The archive contains files at its root.) Alternatively copy individual Markdown files there.

## Architectural choices

- COSE_Sign1 / CBOR, not homemade signature primitives
- Signature of arbitrary content is a core feature, **not** a special case of challenge-response
- Challenge-response is a separate purpose with single-use verifier nonces
- TQSL/LoTW-backed X.509 keys are an optional, policy-sensitive identity backend
- Short on-air artifacts locate complete proofs; they never replace cryptographic verification
- HTTPS proof hosting is optional; direct offline verification must work
- Opulent Voice is an optional consumer/adapter, not a required transport

## Layout

```text
arap/
├── README.md
├── spec/
│   └── ARAP-v0.1.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── IMPLEMENTATION-PLAN.md
│   ├── PIXELQSO-INTEGRATION.md
│   └── TQSL-RESEARCH.md
└── test-vectors/
    └── README.md
```

## License

Specification text is offered under CC0-1.0 for ease of adoption, subject to later project owner confirmation. Future application code should choose its own explicit open-source license. This scaffold does not copy code from TQSL or Opulent Voice.