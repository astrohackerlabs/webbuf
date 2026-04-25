/**
 * Audit tests for @webbuf/slhdsa
 *
 * Validates the implementation against official NIST ACVP test vectors
 * for FIPS 205 (SLH-DSA). See test/vectors/README.md for sources.
 *
 * The NIST ACVP-Server FIPS 205 vector files do not cover all 12 parameter
 * sets — only the subsets NIST chose to publish. The audit suite runs
 * whatever vectors are provided.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import * as slh from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

const __dirname = dirname(fileURLToPath(import.meta.url));

type ParamSet =
  | "SLH-DSA-SHA2-128s"
  | "SLH-DSA-SHA2-128f"
  | "SLH-DSA-SHA2-192s"
  | "SLH-DSA-SHA2-192f"
  | "SLH-DSA-SHA2-256s"
  | "SLH-DSA-SHA2-256f"
  | "SLH-DSA-SHAKE-128s"
  | "SLH-DSA-SHAKE-128f"
  | "SLH-DSA-SHAKE-192s"
  | "SLH-DSA-SHAKE-192f"
  | "SLH-DSA-SHAKE-256s"
  | "SLH-DSA-SHAKE-256f";

interface Sizes {
  seedSize: number;
  vkSize: number;
  skSize: number;
  sigSize: number;
}

const SIZES: Record<ParamSet, Sizes> = {
  "SLH-DSA-SHA2-128s": { seedSize: 16, vkSize: 32, skSize: 64, sigSize: 7856 },
  "SLH-DSA-SHA2-128f": { seedSize: 16, vkSize: 32, skSize: 64, sigSize: 17088 },
  "SLH-DSA-SHA2-192s": { seedSize: 24, vkSize: 48, skSize: 96, sigSize: 16224 },
  "SLH-DSA-SHA2-192f": { seedSize: 24, vkSize: 48, skSize: 96, sigSize: 35664 },
  "SLH-DSA-SHA2-256s": { seedSize: 32, vkSize: 64, skSize: 128, sigSize: 29792 },
  "SLH-DSA-SHA2-256f": { seedSize: 32, vkSize: 64, skSize: 128, sigSize: 49856 },
  "SLH-DSA-SHAKE-128s": { seedSize: 16, vkSize: 32, skSize: 64, sigSize: 7856 },
  "SLH-DSA-SHAKE-128f": { seedSize: 16, vkSize: 32, skSize: 64, sigSize: 17088 },
  "SLH-DSA-SHAKE-192s": { seedSize: 24, vkSize: 48, skSize: 96, sigSize: 16224 },
  "SLH-DSA-SHAKE-192f": { seedSize: 24, vkSize: 48, skSize: 96, sigSize: 35664 },
  "SLH-DSA-SHAKE-256s": {
    seedSize: 32,
    vkSize: 64,
    skSize: 128,
    sigSize: 29792,
  },
  "SLH-DSA-SHAKE-256f": {
    seedSize: 32,
    vkSize: 64,
    skSize: 128,
    sigSize: 49856,
  },
};

interface KeyGenTest {
  tcId: number;
  skSeed: string;
  skPrf: string;
  pkSeed: string;
  sk: string;
  pk: string;
}

interface SigGenTest {
  tcId: number;
  sk: string;
  message: string;
  signature: string;
  additionalRandomness?: string;
}

interface SigVerTest {
  tcId: number;
  testPassed: boolean;
  pk: string;
  message: string;
  signature: string;
}

interface KeyGenGroup {
  parameterSet: ParamSet;
  tests: KeyGenTest[];
}

interface SigGenGroup {
  parameterSet: ParamSet;
  deterministic: boolean;
  tests: SigGenTest[];
}

interface SigVerGroup {
  parameterSet: ParamSet;
  tests: SigVerTest[];
}

const keygenVectors = JSON.parse(
  readFileSync(join(__dirname, "vectors", "keygen.json"), "utf-8"),
) as { testGroups: KeyGenGroup[] };

const siggenVectors = JSON.parse(
  readFileSync(join(__dirname, "vectors", "siggen.json"), "utf-8"),
) as { testGroups: SigGenGroup[] };

const sigverVectors = JSON.parse(
  readFileSync(join(__dirname, "vectors", "sigver.json"), "utf-8"),
) as { testGroups: SigVerGroup[] };

interface Impl {
  keypair: (
    skSeed: FixedBuf<number>,
    skPrf: FixedBuf<number>,
    pkSeed: FixedBuf<number>,
  ) => { verifyingKey: FixedBuf<number>; signingKey: FixedBuf<number> };
  sign: (
    sk: FixedBuf<number>,
    msg: WebBuf,
    rnd?: FixedBuf<number>,
  ) => FixedBuf<number>;
  verify: (
    vk: FixedBuf<number>,
    msg: WebBuf,
    sig: FixedBuf<number>,
  ) => boolean;
}

const IMPLS: Record<ParamSet, Impl> = {
  "SLH-DSA-SHA2-128s": {
    keypair: slh.slhDsaSha2_128sKeyPair as Impl["keypair"],
    sign: slh.slhDsaSha2_128sSignInternal as Impl["sign"],
    verify: slh.slhDsaSha2_128sVerifyInternal as Impl["verify"],
  },
  "SLH-DSA-SHA2-128f": {
    keypair: slh.slhDsaSha2_128fKeyPair as Impl["keypair"],
    sign: slh.slhDsaSha2_128fSignInternal as Impl["sign"],
    verify: slh.slhDsaSha2_128fVerifyInternal as Impl["verify"],
  },
  "SLH-DSA-SHA2-192s": {
    keypair: slh.slhDsaSha2_192sKeyPair as Impl["keypair"],
    sign: slh.slhDsaSha2_192sSignInternal as Impl["sign"],
    verify: slh.slhDsaSha2_192sVerifyInternal as Impl["verify"],
  },
  "SLH-DSA-SHA2-192f": {
    keypair: slh.slhDsaSha2_192fKeyPair as Impl["keypair"],
    sign: slh.slhDsaSha2_192fSignInternal as Impl["sign"],
    verify: slh.slhDsaSha2_192fVerifyInternal as Impl["verify"],
  },
  "SLH-DSA-SHA2-256s": {
    keypair: slh.slhDsaSha2_256sKeyPair as Impl["keypair"],
    sign: slh.slhDsaSha2_256sSignInternal as Impl["sign"],
    verify: slh.slhDsaSha2_256sVerifyInternal as Impl["verify"],
  },
  "SLH-DSA-SHA2-256f": {
    keypair: slh.slhDsaSha2_256fKeyPair as Impl["keypair"],
    sign: slh.slhDsaSha2_256fSignInternal as Impl["sign"],
    verify: slh.slhDsaSha2_256fVerifyInternal as Impl["verify"],
  },
  "SLH-DSA-SHAKE-128s": {
    keypair: slh.slhDsaShake_128sKeyPair as Impl["keypair"],
    sign: slh.slhDsaShake_128sSignInternal as Impl["sign"],
    verify: slh.slhDsaShake_128sVerifyInternal as Impl["verify"],
  },
  "SLH-DSA-SHAKE-128f": {
    keypair: slh.slhDsaShake_128fKeyPair as Impl["keypair"],
    sign: slh.slhDsaShake_128fSignInternal as Impl["sign"],
    verify: slh.slhDsaShake_128fVerifyInternal as Impl["verify"],
  },
  "SLH-DSA-SHAKE-192s": {
    keypair: slh.slhDsaShake_192sKeyPair as Impl["keypair"],
    sign: slh.slhDsaShake_192sSignInternal as Impl["sign"],
    verify: slh.slhDsaShake_192sVerifyInternal as Impl["verify"],
  },
  "SLH-DSA-SHAKE-192f": {
    keypair: slh.slhDsaShake_192fKeyPair as Impl["keypair"],
    sign: slh.slhDsaShake_192fSignInternal as Impl["sign"],
    verify: slh.slhDsaShake_192fVerifyInternal as Impl["verify"],
  },
  "SLH-DSA-SHAKE-256s": {
    keypair: slh.slhDsaShake_256sKeyPair as Impl["keypair"],
    sign: slh.slhDsaShake_256sSignInternal as Impl["sign"],
    verify: slh.slhDsaShake_256sVerifyInternal as Impl["verify"],
  },
  "SLH-DSA-SHAKE-256f": {
    keypair: slh.slhDsaShake_256fKeyPair as Impl["keypair"],
    sign: slh.slhDsaShake_256fSignInternal as Impl["sign"],
    verify: slh.slhDsaShake_256fVerifyInternal as Impl["verify"],
  },
};

describe("Audit: NIST ACVP keyGen test vectors (FIPS 205)", () => {
  for (const group of keygenVectors.testGroups) {
    const sizes = SIZES[group.parameterSet];
    const impl = IMPLS[group.parameterSet];
    describe(group.parameterSet, () => {
      for (const t of group.tests) {
        it(`tcId ${String(t.tcId)}: deterministic keygen matches expected pk and sk`, () => {
          const skSeed = FixedBuf.fromHex(sizes.seedSize, t.skSeed);
          const skPrf = FixedBuf.fromHex(sizes.seedSize, t.skPrf);
          const pkSeed = FixedBuf.fromHex(sizes.seedSize, t.pkSeed);
          const out = impl.keypair(skSeed, skPrf, pkSeed);
          expect(out.verifyingKey.toHex().toLowerCase()).toBe(
            t.pk.toLowerCase(),
          );
          expect(out.signingKey.toHex().toLowerCase()).toBe(
            t.sk.toLowerCase(),
          );
        });
      }
    });
  }
});

describe("Audit: NIST ACVP sigGen test vectors (FIPS 205)", () => {
  for (const group of siggenVectors.testGroups) {
    const sizes = SIZES[group.parameterSet];
    const impl = IMPLS[group.parameterSet];
    const variant = group.deterministic ? "deterministic" : "hedged";
    describe(`${group.parameterSet} (${variant})`, () => {
      for (const t of group.tests) {
        it(`tcId ${String(t.tcId)}: sign_internal matches expected signature`, () => {
          const sk = FixedBuf.fromHex(sizes.skSize, t.sk);
          const msg = WebBuf.fromHex(t.message);
          const rnd = group.deterministic
            ? undefined
            : FixedBuf.fromHex(sizes.seedSize, t.additionalRandomness!);
          const sig = impl.sign(sk, msg, rnd);
          expect(sig.toHex().toLowerCase()).toBe(t.signature.toLowerCase());
        });
      }
    });
  }
});

describe("Audit: NIST ACVP sigVer test vectors (FIPS 205)", () => {
  for (const group of sigverVectors.testGroups) {
    const sizes = SIZES[group.parameterSet];
    const impl = IMPLS[group.parameterSet];
    describe(group.parameterSet, () => {
      for (const t of group.tests) {
        it(`tcId ${String(t.tcId)}: verify_internal matches testPassed=${String(t.testPassed)}`, () => {
          const pk = FixedBuf.fromHex(sizes.vkSize, t.pk);
          const msg = WebBuf.fromHex(t.message);
          // Some NIST negative-test vectors deliberately use wrong-size
          // signatures; FixedBuf rejects them at construction. Treat that
          // as a failed verification (which matches testPassed=false).
          let valid: boolean;
          try {
            const sig = FixedBuf.fromHex(sizes.sigSize, t.signature);
            valid = impl.verify(pk, msg, sig);
          } catch {
            valid = false;
          }
          expect(valid).toBe(t.testPassed);
        });
      }
    });
  }
});
