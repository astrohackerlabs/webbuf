# @webbuf/mldsa

ML-DSA (FIPS 204) post-quantum digital signatures for WebBuf.

## Preferred API

Use the message-level APIs for application code. They apply the FIPS 204 domain
and context separation rules and default to hedged signing by generating
randomness with the platform CSPRNG through `FixedBuf.fromRandom`.

```typescript
const { verifyingKey, signingKey } = mlDsa65KeyPair();
const signature = mlDsa65Sign(signingKey, message, context);
const ok = mlDsa65Verify(verifyingKey, message, signature, context);
```

The preferred APIs are available for ML-DSA-44, ML-DSA-65, and ML-DSA-87. Two
calls to `mlDsa*Sign(sk, msg)` with identical inputs produce different
signatures because each call samples fresh randomness — this matches FIPS 204
§3.6 best practice and `@webbuf/slhdsa`'s default.

## Deterministic And Internal APIs

Seeded key generation and deterministic signing aliases are available for
reproducible tests and advanced protocol work:

```typescript
mlDsa65KeyPairDeterministic(seed);
mlDsa65SignDeterministic(signingKey, message, context);
```

`mlDsa*SignDeterministic(...)` produces identical bytes for identical inputs
(rnd = 0^32 per FIPS 204 §5.4 deterministic variant).

The `mlDsa*SignInternal(...)` and `mlDsa*VerifyInternal(...)` functions remain
public for ACVP vectors and low-level conformance work. They expose FIPS 204
internal primitives (`Sign_internal` / `Verify_internal`) and should not be the
default application-facing API.

## Testing

The package keeps NIST ACVP vector tests for the internal interface and adds
round-trip and context-separation tests for the preferred message-level API.
