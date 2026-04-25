# NIST ACVP test vectors for ML-DSA

`keygen.json`, `siggen.json`, and `sigver.json` are the "internal projection"
files from the NIST [ACVP-Server][1] repository, taken from commit
[65370b861b96efd30dfe0daae607bde26a78a5c8][2]:

- `keygen.json` ← `gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json`
- `siggen.json` ← `gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json`
- `sigver.json` ← `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`

These vectors test the FIPS 204 internal interface (`ML-DSA.Sign_internal` /
`ML-DSA.Verify_internal`) — the message field is the pre-formatted M' and
verification skips the external context/domain handling.

For sigGen tests with `deterministic = true`, the FIPS 204 deterministic
variant uses `rnd = 0^32`. For `deterministic = false`, `rnd` is provided
explicitly in the test vector.

[1]: https://github.com/usnistgov/ACVP-Server
[2]: https://github.com/usnistgov/ACVP-Server/commit/65370b861b96efd30dfe0daae607bde26a78a5c8
