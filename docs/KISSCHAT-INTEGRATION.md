# KISSChat content profile

The ARAP-facing KISSChat message schema and its signed bytes are specified in
the [KISSChat-message-v1 profile](../../kiss_chat/docs/ARAP-CONTENT-PROFILE.md)
in the KISSChat project. ARAP provides the independent Go canonicalizer in
`adapters/kisschat`; its media type and context constants are the values callers
must pass to `SignContent` and `VerifyContentWithTrust`:

- `application/vnd.kisschat.message+json`
- `kisschat/message-v1`
- canonicalization `identity-v1`

The profile authenticates the message origin and content, not the RF route or
immediate peer. KISSChat sends its body before attempting optional signing, so
ARAP availability, key state or signing failure cannot block message delivery.
The Go adapter performs schema-bound validation and emits deterministic UTF-8
JSON; it does not make trust decisions or choose a cryptographic algorithm.
