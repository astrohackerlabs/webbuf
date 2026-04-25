# @webbuf/mlkem

ML-KEM (FIPS 203) post-quantum key encapsulation for WebBuf.

## Preferred API

Use the high-level functions for application code. They generate required
entropy with the platform CSPRNG through `FixedBuf.fromRandom`.

```typescript
const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
const { ciphertext, sharedSecret } = mlKem768Encapsulate(encapsulationKey);
const recovered = mlKem768Decapsulate(decapsulationKey, ciphertext);
```

The preferred APIs are available for ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

## Deterministic API

Deterministic aliases are available for test vectors, reproducible tests, and
advanced protocol work:

```typescript
mlKem768KeyPairDeterministic(d, z);
mlKem768EncapsulateDeterministic(encapsulationKey, m);
```

The legacy overloads `mlKem*KeyPair(d, z)` and
`mlKem*Encapsulate(encapsulationKey, m)` remain supported for compatibility.
Prefer the explicit `Deterministic` names when writing new low-level code.

## Testing

The package keeps NIST ACVP vector tests for the deterministic interface and
adds round-trip tests for the preferred high-level API.
