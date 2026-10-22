# Application identity lifecycle

This guide describes key creation, authorization, rotation, and LoTW-backed
identity refresh for applications using ARAP's public Go or Python interfaces.
The application owns private-key custody, backup, access control, and the
decision to authorize a callsign/key for a purpose.

## Local Ed25519 identity

1. Generate a new ARAP Ed25519 key with `identity.GenerateEncryptedKeyPair`
   (or `arap keygen`). Keep the encrypted private-key file and public-key file
   together in the application's protected identity store.
2. Record the public key fingerprint using `protocol.KeyID`. A fingerprint is
   an identifier, not proof of callsign ownership.
3. Establish trust through the application's chosen policy. `TrustStore.Add`
   grants only the supplied purposes; `TrustStore.Disable` revokes local
   authorization. Persist updates with `identity.SaveTrust`.
4. Back up the encrypted private-key file to protected storage and keep its
   passphrase in a separate recovery channel. Do not put the key and passphrase
   together in an unencrypted archive or sync location. Keep the matching public
   key and fingerprint with the backup so the identity can be recognized.

To restore, copy the encrypted key into the protected identity store, enter its
passphrase through the CLI/desktop prompt or standard input, and confirm that
the derived public key has the fingerprint recorded with the backup. Do not
overwrite an existing identity file. If the passphrase or encrypted backup is
lost, the key cannot be recovered; generate a new key and enroll/trust it as a
new identity.

If a key is lost or suspected compromised, disable its callsign/key binding in
each relying application's local enrollment store and disable its public key in
each local trust store. These actions stop those applications from accepting
it; they do not notify other verifiers or revoke a certificate at ARRL. Tell
each relying application through its normal administrative channel if its
policy requires coordinated removal. Generate a new key and complete fresh
enrollment before relying on the replacement. Do not copy or re-encrypt the
old private key as part of rotation.

## Replacing an LoTW-enrolled key

An enrollment is bound to the exact ARAP key fingerprint and leaf Callsign
Certificate. Status refresh can update neither identity field. To replace the
ARAP key:

1. Generate a new ARAP key and publish only its public key.
2. Issue a fresh enrollment challenge addressed to the relying application,
   containing the new key and the exact purposes to grant.
3. Have the station respond using the Callsign Certificate and the new ARAP
   key. The relying application independently validates the fresh challenge,
   response signatures, configured certificate roots, callsign, purpose policy,
   and current status evidence.
4. Persist the new binding as a separate identity. Confirm it works for the
   intended operation before disabling the old binding.
5. Disable the old binding in each relying application's local policy. Retain
   only the public evidence needed for audit or refresh; do not transfer the
   old private key to the new identity.

Use the application's enrollment database operations or
`lotwenroll.SQLiteStore.Disable`. Never implement rotation by editing the
SQLite database directly. A successful status refresh is not a replacement
enrollment and cannot restore a disabled or expired key.

## Evidence and transfer between applications

The portable proof of control is the encoded enrollment response returned by
`lotwenroll.EncodeResponse` or the Python `response` bytes. It contains public
challenge and certificate-chain evidence, not a private key or a verifier's
local trust decision. Keep the original challenge audience and purpose claims.

A receiving application must not import a previous application's accepted
database row or copy its `trusted` result. It evaluates the response under its
own configured roots and purpose policy, obtains status evidence according to
its own freshness policy, and requires a challenge issued for its own audience.
Challenge-response evidence is audience-bound and single-use; it is not a
portable login token. If the recipient or purpose changes, issue a new
challenge and complete a fresh enrollment. Key endorsements are separately
portable signed statements and must be checked against the receiving
application's explicitly configured roots and purpose policy.

Status refresh is always an explicit application operation. It revalidates the
retained certificate chain and exact key/certificate binding; it does not
silently contact the network during content or challenge verification.
