# Python application integration

`arap_interop` is the version 1 Python subprocess interface for applications
that do not use the Go packages. It exposes content signing/verification,
one way and mutual challenge authentication, and key endorsement through a
single `ArapClient`. It also exposes experimental LoTW enrollment challenge,
response, verification, status refresh, listing, and disablement operations. Binary requests,
responses, proofs, and endorsement chains
are Python `bytes`; the wrapper handles temporary files and does not parse or
rewrite those protocol bytes.
`generate_keypair(passphrase=...)` returns an age-armored encrypted PKCS#8
private key and an SPKI public-key PEM as bytes. Persist them in the consuming
application's protected identity store; ARAP removes its temporary copies
before returning.
Use `fingerprint(public_key_bytes)` to obtain the key ID needed by
`disable_trust`, even when that key has not signed an ARAP proof.

The wrapper requires Python 3.10+ and an installed ARAP executable. Add this
directory to `PYTHONPATH` or install it in the consuming application's own
environment:

```sh
PYTHONPATH=/path/to/arap/interop/python python3 app.py
```

For an editable local install, run this in the application's environment:

```sh
python3 -m pip install -e /path/to/arap/interop/python
```

```python
from arap_interop import ArapClient, ArapError

arap = ArapClient("/usr/local/bin/arap", timeout=20)
signed = arap.sign_content(
    b"exact bytes to sign", key="station.age", callsign="AG7SU",
    media_type="application/octet-stream", context="my-app/object/v1",
    passphrase="read this from your secret store",
)
try:
    result = arap.verify_content(
        signed["proof"], b"exact bytes to sign", public_key="station.pub.pem",
        trust_store="trust.json", media_type="application/octet-stream",
        context="my-app/object/v1", callsign="AG7SU",
    )
except ArapError as exc:
    if exc.code == "rejected":
        raise PermissionError("content proof rejected by local policy") from exc
    raise
assert result["protocol_version"] == 1
assert result["result"]["overall_policy"] == "accepted"
```

Every successful call returns `{"protocol_version": 1, "ok": true,
"result": ...}`. Binary-producing methods add a named `bytes` field, such as
`proof`, `request`, `response`, or `chain`. `ArapError` carries stable `code`
and `exit_status` fields; verification rejection is `rejected` (1), incomplete
verification is `incomplete` (3), timeout is `timeout` (124), and execution or
input failures are `operation_error` (2). CLI diagnostic text is deliberately
not treated as a stable API. Resolver operations preserve specific stable
codes such as `not_found`, `ambiguous`, `unavailable`, and `invalid_response`.

For optional public reference hosting, `publish_proof(proof, server=...)` and
`publish_key(public_key, server=...)` return identifiers in `result`.
`resolve_proof(reference, servers=[...])` returns proof bytes in `proof`, and
`fetch_key(fingerprint, servers=[...])` returns public-key bytes in
`public_key`. These methods do not establish trust: callers must verify
retrieved proofs and apply their own identity policy.

## State and security ownership

- The caller owns key files, trust stores, challenge databases, certificate
  enrollment databases, and their backup, access, and lifecycle policy.
- Use `add_trust`, `list_trust`, and `disable_trust` to manage the wrapper's
  local trust file without editing its JSON representation. Each `add_trust`
  call authorizes one explicit purpose; after a disabled binding is re-enabled,
  only the newly selected purpose is restored.
- Call `verify_challenge` / `verify_mutual_challenges` only at the verifier that
  owns the challenge database. A successful response consumes its challenge;
  replay is rejected. Mutual verification checks and consumes the pair together.
- If application transport fails after `issue_challenge`, call
  `cancel_challenge(request, store=...)` to cancel it while it is still pending.
  A consumed challenge is retained.
- Supply an application session binding to the mutual issue and verify calls.
  Use the same opaque bytes for both calls; ARAP does not negotiate or create
  the application session.
- The caller chooses trust bindings, expected purpose, root authority, and
  enrollment status policy. The wrapper performs no implicit network lookup.
- LoTW enrollment response signing is experimental. It uses TQSL's supported
  RSA-SHA1 signature only for the short-lived enrollment assertion and requires
  the native TQSL helper; it may require a separate TQSL certificate password.
  The `allow_legacy_rsa_sha1` argument remains accepted for compatibility.
  `tqsl_directory` can select an explicit
  TQSL data directory; the default remains the user's normal TQSL configuration.
  Verification depends on configured
  TQSL/ARRL roots and the live certificate-status provider. The evidence is
  evaluated under ARAP policy and is not an ARRL-approved login or endorsement.
- The passphrase argument is sent only over child stdin and is not included in
  argv, output, or exception messages. Load it from an OS secret store; avoid
  hard-coding it as in the illustrative snippet above.
- Every subprocess call has a timeout. On timeout the child is terminated by
  Python's subprocess implementation; the wrapper reports `timeout`.
- Temporary files are private to the calling process and removed when each
  method returns. Persist any returned bytes using the consuming application's
  own atomic and access-controlled storage.

The Go consumer examples remain the preferred in-process integration when the
application is written in Go. The Python wrapper is a convenience boundary over
the CLI, not a C ABI or a network service.

For enrolled content identity, request `content-signature` when creating the
enrollment challenge, pass it again as an explicit `allowed_purposes` value to
`verify_enrollment`, then call content verification with the enrollment store:

```python
checked = arap.verify_content(
    proof, content, public_key="station.pub.pem", enrollment_store="enrollment.sqlite",
    max_enrollment_status_age="24h", media_type="application/octet-stream",
    context="my-app/object/v1",
)
```

Omitted purposes create a version 1
challenge-response-only binding. Content signatures do not retroactively prove
that a callsign certificate was valid at the signature's asserted creation time;
the verifier evaluates the current binding and status freshness at verification.

Run the integration checks from the repository root:

```sh
PYTHONPATH=interop/python python3 -m unittest interop.python.test_client -v
```

To validate the machine error envelope against its JSON Schema, install the
test dependencies and run `python3 scripts/check-machine-interface.py`.
`python3 scripts/check-installed-python-consumer.py` additionally builds and
installs a wheel, changes to a temporary directory outside the checkout, and
tests content, PixelQSO, one-way and mutual challenges, endorsements, replay
and wrong-session rejection, and proof/key publication through an isolated
keyserver. Pass `--bundle ARCHIVE --target TARGET` to exercise the CLI and
keyserver extracted from a desktop archive rather than binaries built from the
checkout.

The suite starts a temporary local ARAP keyserver and checks proof/key publish
and fetch through the public Python methods, including the stable `not_found`
outcome. No remote service or persistent user data is used.
