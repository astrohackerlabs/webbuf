# @webbuf/slhdsa

SLH-DSA (FIPS 205) stateless hash-based post-quantum digital signatures for
WebBuf.

## Preferred API

Use the message-level APIs for application code. They apply FIPS 205 context
separation and default to hedged signing by generating `addrnd` with the
platform CSPRNG through `FixedBuf.fromRandom`.

```typescript
const { verifyingKey, signingKey } = slhDsaSha2_128fKeyPair();
const signature = slhDsaSha2_128fSign(signingKey, message, context);
const ok = slhDsaSha2_128fVerify(verifyingKey, message, signature, context);
```

The preferred APIs are available for all SHA2 and SHAKE SLH-DSA parameter sets.

## Deterministic And Internal APIs

Seeded key generation and deterministic signing aliases are available for
reproducible tests and advanced protocol work:

```typescript
slhDsaSha2_128fKeyPairDeterministic(skSeed, skPrf, pkSeed);
slhDsaSha2_128fSignDeterministic(signingKey, message, context);
```

The `slhDsa*SignInternal(...)` and `slhDsa*VerifyInternal(...)` functions
remain public for ACVP vectors and low-level conformance work. They expose FIPS
205 internal primitives and should not be the default application-facing API.

## Testing

The package keeps NIST ACVP vector tests for the internal interface and adds
round-trip, hedged-signing, deterministic-signing, and context-separation tests
for the preferred message-level API.
