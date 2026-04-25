# NIST ACVP test vectors for SLH-DSA

`keygen.json`, `siggen.json`, and `sigver.json` are the "internal projection"
files from the NIST [ACVP-Server][1] repository, taken from commit
[65370b861b96efd30dfe0daae607bde26a78a5c8][2]:

- `keygen.json` ← `gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json`
- `siggen.json` ← `gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json`
- `sigver.json` ← `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json`

The vectors only cover a subset of the 12 FIPS 205 parameter sets — NIST's
choice. We exercise our wrapper against the subset they provide.

For sigGen tests with `deterministic = true`, the FIPS 205 deterministic
variant uses `pkSeed` as the randomizer (`opt_rand = None` in our wrapper).
For `deterministic = false`, the test provides `additionalRandomness`.

[1]: https://github.com/usnistgov/ACVP-Server
[2]: https://github.com/usnistgov/ACVP-Server/commit/65370b861b96efd30dfe0daae607bde26a78a5c8
