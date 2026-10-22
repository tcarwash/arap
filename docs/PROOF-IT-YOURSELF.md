# Prove ARAP content signing works

This walkthrough creates a throwaway Ed25519 key, signs a file, verifies it
under local trust, then changes the file and confirms verification rejects it.
It runs locally and does not contact TQSL, ARRL, or a network service.

## Run the proof

From the ARAP repository root:

```sh
go build -o ./bin/arap ./cmd/arap

umask 077
DEMO_DIR="$(mktemp -d)"
ARAP_BIN="$PWD/bin/arap"
printf 'Demo only passphrase\nDemo only passphrase\n' |
  "$ARAP_BIN" keygen \
    --private-key "$DEMO_DIR/station.age" \
    --public-key "$DEMO_DIR/station.pub.pem" \
    --passphrase-stdin

printf 'Hello from ARAP.\n' > "$DEMO_DIR/message.txt"

"$ARAP_BIN" trust add \
  --store "$DEMO_DIR/trust.json" \
  --public-key "$DEMO_DIR/station.pub.pem" \
  --callsign K7ABC \
  --purpose content-signature

printf 'Demo only passphrase\n' |
  "$ARAP_BIN" sign-content \
    --key "$DEMO_DIR/station.age" \
    --callsign K7ABC \
    --input "$DEMO_DIR/message.txt" \
    --media-type text/plain \
    --context my-app/message-v1 \
    --out "$DEMO_DIR/message.cose" \
    --passphrase-stdin

"$ARAP_BIN" verify-content \
  --proof "$DEMO_DIR/message.cose" \
  --input "$DEMO_DIR/message.txt" \
  --public-key "$DEMO_DIR/station.pub.pem" \
  --trust-store "$DEMO_DIR/trust.json" \
  --expect-media-type text/plain \
  --expect-context my-app/message-v1 \
  --expect-callsign K7ABC
```

The last command should exit with status `0` and print JSON containing
`"overall_policy":"accepted"`, `"cryptographic_signature":"valid"`, and
`"content_integrity":"valid"`.

Now change the message and run the same verification command again:

```sh
printf 'This is different content.\n' > "$DEMO_DIR/message.txt"

"$ARAP_BIN" verify-content \
  --proof "$DEMO_DIR/message.cose" \
  --input "$DEMO_DIR/message.txt" \
  --public-key "$DEMO_DIR/station.pub.pem" \
  --trust-store "$DEMO_DIR/trust.json" \
  --expect-media-type text/plain \
  --expect-context my-app/message-v1 \
  --expect-callsign K7ABC
```

This time ARAP should report a rejected policy, with invalid content integrity,
and exit with status `1`. The proof still has the original signature; changing
the content changes its digest, so it no longer matches.

When finished, remove the throwaway key, trust store, message, and proof:

```sh
rm -rf "$DEMO_DIR"
```

## What `trust add` means

In this walkthrough, `trust add` is a test setup shortcut. It writes a local
authorization to `trust.json`: “this public key is trusted to make
`content-signature` proofs claiming the callsign `K7ABC`.” It does not contact
the callsign owner, check a Callsign Certificate, or prove that the key belongs
to a real operator. The key and trust store are throwaway and local to this
test.

For real use, each receiving application needs a reason to authorize a
callsign/key pair. An operator can share a key fingerprint over a separately
verified channel and the receiver can choose to add that key locally. Or the
receiver can validate ARAP's LoTW/TQSL enrollment evidence under its configured
roots and status policy, granting only the purposes requested and accepted in
that enrollment. That enrollment is ARAP authentication evidence; it is not an
ARRL-approved login or endorsement. A valid signature without an accepted
trust decision proves possession of a key, but does not by itself establish
callsign authorization.

Trust is local to the receiving application. Adding a key on one computer does
not automatically authorize it in other ARAP consumers. See
[`IDENTITY-LIFECYCLE.md`](IDENTITY-LIFECYCLE.md) for key custody, replacement,
and enrollment details, and [`MACHINE-INTERFACE.md`](MACHINE-INTERFACE.md) for
the versioned Python API.
