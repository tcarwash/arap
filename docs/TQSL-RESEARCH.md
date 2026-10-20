# TQSL integration research checklist

Goal: determine whether existing LoTW callsign credentials can safely and appropriately sign ARAP COSE proof messages without introducing a new identity authority.

## Verify before claiming support

1. Current TrustedQSL `tqsllib` supported APIs, certificate enumeration, key unlocking and signing behavior.
2. Whether current TQSL interfaces can sign arbitrary data, or only canonical LoTW QSO records.
3. PKCS#12 export support and actual sample certificate key type, algorithm, extensions, permitted key usages, EKUs and policies.
4. Whether using this certificate for non-LoTW signatures is authorized/supported by ARRL; contact maintainers if unclear.
5. Reliable callsign extraction and portable/multiple-callsign handling.
6. Trust-anchor distribution, certificate chain validation, expiration, revocation mechanisms, and reporting of unavailable status.
7. Safe handling of private-key exports; ideally separate process or on-demand non-exporting signer where API permits.
8. COSE algorithm choice for a real TQSL key; include correct algorithm parameters and signature byte encoding.

## Do not assume

- A certificate can be used for any purpose solely because its private key can sign bytes.
- A mathematically valid certificate signature proves current certificate validity or operator presence.
- LoTW provides a public identity/certificate directory or standard revocation endpoint.
- COSE X.509 header references automatically validate callsigns or policies.

## Prototype gates

- [ ] Inspect current source and public documentation
- [ ] Inspect a user-consented test certificate (never check private keys into git)
- [ ] Sign arbitrary test content with a key generated specifically for tests
- [ ] Verify certificate chain and purpose under clear policy
- [ ] Get maintainers' feedback on non-LoTW usage
- [ ] Add COSE vectors for a supported algorithm
- [ ] Only then label the backend `tqsl-backed`