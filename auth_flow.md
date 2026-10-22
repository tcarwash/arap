# ARRL-backed ARAP authentication flow

This diagram shows how a TQSL Callsign Certificate is used to enroll an ARAP
Ed25519 key, and how that enrolled key signs application messages. TQSL signs
the enrollment challenge; ARAP signs messages with Ed25519 afterward.

```mermaid
flowchart TD
    subgraph Enroll[One-time enrollment per callsign, ARAP key, verifier, and purpose]
        V[Verifier chooses callsign, audience, ARAP public key, and purpose] --> I[Issue fresh, short-lived enrollment challenge]
        I --> R[Send challenge to station]
        R --> S[Station confirms certificate and selects serial if needed]
        S --> T[TQSL signs challenge with Callsign Certificate]
        S --> A[ARAP Ed25519 key signs same challenge]
        T --> P[Return certificate chain and both signatures]
        A --> P
        P --> C[Verifier checks audience, freshness, and one-time challenge]
        C --> X[Validate certificate chain against configured TQSL/ARRL roots]
        X --> L[Check certificate callsign and current LoTW serial status]
        L --> D{All checks pass and requested purpose is allowed?}
        D -->|Yes| B[Persist callsign, ARAP key, certificate, purpose, and status evidence]
        D -->|No| N[Reject enrollment; do not authorize key]
    end

    subgraph Messages[Each message after enrollment]
        M[Application canonicalizes message bytes] --> MS[ARAP signs bytes with enrolled Ed25519 private key]
        MS --> W[Send message and detached COSE proof]
        W --> VFY[Receiver checks proof, content digest, expected profile, and signer key]
        B --> TS[Check binding enabled, purpose allowed, certificate unexpired, and status evidence fresh]
        TS -->|Accepted| VFY
        VFY --> Q{Signature, content, and enrollment policy accepted?}
        Q -->|Yes| OK[Accept as authenticated under ARAP policy]
        Q -->|No| REJ[Reject or show untrusted]
    end

    subgraph Refresh[Status refresh when evidence approaches its age limit]
        B --> AGE[Stored LoTW status evidence ages; default maximum is 24 hours]
        AGE --> REF[Verifier rechecks retained certificate chain and queries LoTW status]
        REF --> RF{Chain, certificate, and fresh status remain valid?}
        RF -->|Yes| UPD[Update status evidence for the same key, certificate, and purposes]
        RF -->|No| DIS[Keep binding unavailable]
        UPD --> TS
    end
```

## What each signature proves

- The TQSL signature proves that the Callsign Certificate's private key signed
  this fresh, audience-bound enrollment challenge. TQSL handles that private
  key; ARAP does not export it.
- The enrollment challenge also binds the exact ARAP Ed25519 public-key
  fingerprint and requested purpose. The verifier independently checks the
  matching Ed25519 signature before storing the binding.
- Later messages are signed by the ARAP Ed25519 key. TQSL is not invoked for
  each message.
- Acceptance means the receiving application accepted this evidence under its
  ARAP policy. It is not an ARRL-approved login or endorsement, and it does not
  prove physical RF presence.

Enrollment is repeated when the ARAP key or Callsign Certificate is replaced,
or when a new verifier needs its own audience-bound binding. Status refresh is
separate: it obtains fresh LoTW status for the same enrolled binding. ARAP
provides the refresh operation but does not schedule it automatically.

See the [enrollment design](docs/LOTW-BINDING-DESIGN.md) for CLI commands and
validation details, and the [identity lifecycle guide](docs/IDENTITY-LIFECYCLE.md)
for key replacement and status policy.
