# ARAP station challenges

Challenge requests are canonical CBOR files and responses are ordinary ARAP COSE_Sign1 proofs using the separate challenge profile. The 16-byte nonce is generated from the system CSPRNG. The default lifetime is 120 seconds, the maximum is 600 seconds, and the allowed future skew is 30 seconds. See [the CDDL](../spec/ARAP-challenge-v1.cddl).

## Requester

```sh
arap challenge issue --requester K7ABC --responder AG7SU \
  --store ~/.local/state/arap/challenges.sqlite --out challenge.cbor
```

The command persists the outstanding request before exposing its file. Keep the database with the requester; the responder does not need it.

Applications should use `challenge.IssueRequest` before publishing request bytes.
If their transport fails before delivery, `challenge.CancelRequest` (or
`arap challenge cancel --request challenge.cbor --store challenges.sqlite`)
removes the request only while it is pending. Consumed requests are retained.
The Python interface exposes the same operation as `cancel_challenge`.

## Responder

```sh
arap challenge respond --request challenge.cbor --callsign AG7SU \
  --key station-private.pem --out response.cose
```

The signing key callsign must match the request's responder. The command rejects expired and mismatched requests.

## Verify and consume

First add the responder key to local trust specifically for `challenge-response`:

```sh
arap trust add --store trust.json --public-key ag7su.pub.pem \
  --callsign AG7SU --purpose challenge-response
```

Then verify using the same requester's database used to issue the challenge:

```sh
arap challenge verify-response --request challenge.cbor \
  --response response.cose --public-key ag7su.pub.pem \
  --trust-store trust.json --store ~/.local/state/arap/challenges.sqlite \
  --requester K7ABC
```

Alternatively, a verified enrollment binding can authorize only the
`challenge-response` proof purpose:

```sh
arap challenge verify-response --request challenge.cbor \
  --response response.cose --public-key ag7su.pub.pem \
  --enrollment-store ~/.local/state/arap/lotw-enrollment.sqlite \
  --store ~/.local/state/arap/challenges.sqlite --requester K7ABC
```

The default maximum age for the enrollment's timestamped certificate-status
evidence is 24 hours; use `--max-enrollment-status-age` to choose a different
bound. Expired certificates, stale/unknown status, and disabled enrollment
bindings do not authorize the response. Enrollment never grants content
signature trust. `arap enrollment list|disable` inspects or disables persisted
bindings. The separate `arap enrollment issue` command creates a verifier-side
LoTW enrollment challenge; it does not sign or verify a response and is not
interchangeable with the station challenge commands on this page.

The verifier checks the response signature before applying challenge freshness, so a valid but expired response still reports a valid signature while remaining rejected; corrupted bytes report an invalid signature. Only an accepted verification atomically changes the recorded request from pending to consumed. Replays, expired requests, unknown requests, trust failures and store errors do not authenticate. The SQLite file is created with owner-only permissions; keep it backed up and private. Challenge-response proves access to a trusted signing key for a request. It does not prove physical RF presence or prevent a live relay.

## Mutual authentication from an application

The Go API coordinates both directions over one application session. The
coordinating verifier creates and stores two inverse challenges with the same
purpose, validity window and non-empty session binding:

```go
requests, err := challenge.NewMutualRequests(
    store, "K7ABC", "AG7SU", "station-auth", tlsChannelBinding, now, 2*time.Minute,
)
```

Send `requests.FromA` to AG7SU; AG7SU signs it and returns the response as
`responses.FromB`. Send `requests.FromB` to K7ABC; K7ABC signs it and returns
`responses.FromA`. The app then checks both identities together:

```go
result := challenge.VerifyMutualPair(requests, responses, challenge.MutualVerificationConfig{
    VerifierA: verifierA, TrustA: trustA,
    VerifierB: verifierB, TrustB: trustB,
    Store: store, Session: tlsChannelBinding, Now: now,
})
if !result.Accepted {
    // Do not establish the authenticated session.
}
```

The caller must pass the same session binding it used to create the requests.
The verifier checks inverse parties, matching purpose and lifetime, distinct
nonces, both signatures and both trust decisions. The SQLite adapter consumes
both pending challenges in one transaction; a partial pair cannot authenticate
and a replay fails. If either response or trust decision fails, neither request
is consumed, so the caller may retry verification until expiry. Create a fresh
pair after expiry. This coordinated check does not derive an encryption key or
protect the transport by itself; applications must use a separately specified
protocol for those functions.

Run the complete in-process public API example with `go run ./examples/mutual-auth`.
It uses generated in-memory keys and a temporary SQLite challenge store.

## Mutual authentication through the CLI

Create both requests at the verifier, using a unique application binding such
as a TLS exporter value:

```sh
arap challenge mutual-issue --party-a K7ABC --party-b AG7SU \
  --purpose station-auth --session-binding-hex "$SESSION_BINDING_HEX" \
  --store mutual-challenges.sqlite \
  --out-from-a request-from-a.cbor --out-from-b request-from-b.cbor
```

Give `request-from-a.cbor` to AG7SU and `request-from-b.cbor` to K7ABC. Each
side responds with the existing `challenge respond` command using its own
private key. Return both responses to the verifier, which checks them with
separate public keys and trust stores:

```sh
arap challenge mutual-verify \
  --request-from-a request-from-a.cbor --response-from-b response-from-b.cose \
  --request-from-b request-from-b.cbor --response-from-a response-from-a.cose \
  --party-a K7ABC --party-b AG7SU \
  --party-a-public-key k7abc.pub.pem --party-b-public-key ag7su.pub.pem \
  --party-a-trust-store trust-a.json --party-b-trust-store trust-b.json \
  --session-binding-hex "$SESSION_BINDING_HEX" --store mutual-challenges.sqlite
```

Each party's trust store must authorize its own key for
`challenge-response`. Use `--party-a-enrollment-store` and
`--party-b-enrollment-store` instead of or alongside local trust stores when
the verifier has accepted LoTW enrollment records. The verifier accepts the
pair only for the exact expected session binding and consumes both requests
atomically. A failed attempt leaves both pending until expiry; a consumed pair
cannot be reused. The challenge SQLite database must remain at the verifier
that issued the pair.

The desktop Challenge tab exposes the same coordinated workflow under
“Mutual authentication”. Create both requests using one verifier-owned replay
database, send each request to its named peer, and use the responder section to
sign each incoming request. Enter both request/response pairs, both public
keys, each party's trust source, the original session binding, and that same
replay database to verify and consume the pair atomically.
