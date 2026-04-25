# @webbuf/mldsa

ML-DSA (FIPS 204) post-quantum digital signatures for WebBuf.

## Preferred API

Use the message-level APIs for application code. They apply the FIPS 204 domain
and context separation rules and use an empty context by default.

```typescript
const { verifyingKey, signingKey } = mlDsa65KeyPair();
const signature = mlDsa65Sign(signingKey, message, context);
const ok = mlDsa65Verify(verifyingKey, message, signature, context);
```

The preferred APIs are available for ML-DSA-44, ML-DSA-65, and ML-DSA-87.

## Deterministic And Internal APIs

Key generation has deterministic aliases for reproducible tests:

```typescript
mlDsa65KeyPairDeterministic(seed);
```

`mlDsa*Sign(...)` currently uses the standardized deterministic ML-DSA.Sign
variant. The explicit `mlDsa*SignDeterministic(...)` aliases exist so callers
can make that behavior clear in test and protocol code.

The `mlDsa*SignInternal(...)` and `mlDsa*VerifyInternal(...)` functions remain
public for ACVP vectors and low-level conformance work. They expose FIPS 204
internal primitives and should not be the default application-facing API.

## Testing

The package keeps NIST ACVP vector tests for the internal interface and adds
round-trip and context-separation tests for the preferred message-level API.
