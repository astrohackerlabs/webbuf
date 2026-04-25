/**
 * Audit tests for @webbuf/mldsa
 *
 * Validates the implementation against official NIST ACVP test vectors
 * for FIPS 204 (ML-DSA). See test/vectors/README.md for sources.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import {
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
  mlDsa44KeyPair,
  mlDsa44SignInternal,
  mlDsa44VerifyInternal,
  mlDsa65KeyPair,
  mlDsa65SignInternal,
  mlDsa65VerifyInternal,
  mlDsa87KeyPair,
  mlDsa87SignInternal,
  mlDsa87VerifyInternal,
} from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

const __dirname = dirname(fileURLToPath(import.meta.url));

type ParamSet = "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87";

interface KeyGenTest {
  tcId: number;
  seed: string;
  pk: string;
  sk: string;
}

interface SigGenTest {
  tcId: number;
  sk: string;
  message: string;
  signature: string;
  rnd?: string;
}

interface SigVerTest {
  tcId: number;
  testPassed: boolean;
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
  pk: string;
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

const ZERO_RND = FixedBuf.fromHex(
  32,
  "0000000000000000000000000000000000000000000000000000000000000000",
);

function fixed32(hex: string): FixedBuf<32> {
  return FixedBuf.fromHex(32, hex);
}

function runKeyGen(param: ParamSet, seed: FixedBuf<32>): { pk: string; sk: string } {
  switch (param) {
    case "ML-DSA-44": {
      const kp = mlDsa44KeyPair(seed);
      return { pk: kp.verifyingKey.toHex(), sk: kp.signingKey.toHex() };
    }
    case "ML-DSA-65": {
      const kp = mlDsa65KeyPair(seed);
      return { pk: kp.verifyingKey.toHex(), sk: kp.signingKey.toHex() };
    }
    case "ML-DSA-87": {
      const kp = mlDsa87KeyPair(seed);
      return { pk: kp.verifyingKey.toHex(), sk: kp.signingKey.toHex() };
    }
  }
}

function runSign(
  param: ParamSet,
  skHex: string,
  messageHex: string,
  rnd: FixedBuf<32>,
): string {
  const message = WebBuf.fromHex(messageHex);
  switch (param) {
    case "ML-DSA-44": {
      const sk = FixedBuf.fromHex(
        ML_DSA_44.signingKeySize,
        skHex,
      ) as FixedBuf<2560>;
      return mlDsa44SignInternal(sk, message, rnd).toHex();
    }
    case "ML-DSA-65": {
      const sk = FixedBuf.fromHex(
        ML_DSA_65.signingKeySize,
        skHex,
      ) as FixedBuf<4032>;
      return mlDsa65SignInternal(sk, message, rnd).toHex();
    }
    case "ML-DSA-87": {
      const sk = FixedBuf.fromHex(
        ML_DSA_87.signingKeySize,
        skHex,
      ) as FixedBuf<4896>;
      return mlDsa87SignInternal(sk, message, rnd).toHex();
    }
  }
}

function runVerify(
  param: ParamSet,
  pkHex: string,
  messageHex: string,
  signatureHex: string,
): boolean {
  const message = WebBuf.fromHex(messageHex);
  switch (param) {
    case "ML-DSA-44": {
      const pk = FixedBuf.fromHex(
        ML_DSA_44.verifyingKeySize,
        pkHex,
      ) as FixedBuf<1312>;
      const sig = FixedBuf.fromHex(
        ML_DSA_44.signatureSize,
        signatureHex,
      ) as FixedBuf<2420>;
      return mlDsa44VerifyInternal(pk, message, sig);
    }
    case "ML-DSA-65": {
      const pk = FixedBuf.fromHex(
        ML_DSA_65.verifyingKeySize,
        pkHex,
      ) as FixedBuf<1952>;
      const sig = FixedBuf.fromHex(
        ML_DSA_65.signatureSize,
        signatureHex,
      ) as FixedBuf<3309>;
      return mlDsa65VerifyInternal(pk, message, sig);
    }
    case "ML-DSA-87": {
      const pk = FixedBuf.fromHex(
        ML_DSA_87.verifyingKeySize,
        pkHex,
      ) as FixedBuf<2592>;
      const sig = FixedBuf.fromHex(
        ML_DSA_87.signatureSize,
        signatureHex,
      ) as FixedBuf<4627>;
      return mlDsa87VerifyInternal(pk, message, sig);
    }
  }
}

describe("Audit: NIST ACVP keyGen test vectors (FIPS 204)", () => {
  for (const group of keygenVectors.testGroups) {
    describe(group.parameterSet, () => {
      for (const t of group.tests) {
        it(`tcId ${String(t.tcId)}: deterministic keygen matches expected pk and sk`, () => {
          const out = runKeyGen(group.parameterSet, fixed32(t.seed));
          expect(out.pk.toLowerCase()).toBe(t.pk.toLowerCase());
          expect(out.sk.toLowerCase()).toBe(t.sk.toLowerCase());
        });
      }
    });
  }
});

describe("Audit: NIST ACVP sigGen test vectors (FIPS 204)", () => {
  for (const group of siggenVectors.testGroups) {
    const variant = group.deterministic ? "deterministic" : "hedged";
    describe(`${group.parameterSet} (${variant})`, () => {
      for (const t of group.tests) {
        it(`tcId ${String(t.tcId)}: sign_internal matches expected signature`, () => {
          const rnd = group.deterministic ? ZERO_RND : fixed32(t.rnd!);
          const sig = runSign(group.parameterSet, t.sk, t.message, rnd);
          expect(sig.toLowerCase()).toBe(t.signature.toLowerCase());
        });
      }
    });
  }
});

describe("Audit: NIST ACVP sigVer test vectors (FIPS 204)", () => {
  for (const group of sigverVectors.testGroups) {
    describe(group.parameterSet, () => {
      for (const t of group.tests) {
        it(`tcId ${String(t.tcId)}: verify_internal matches testPassed=${String(t.testPassed)}`, () => {
          const valid = runVerify(
            group.parameterSet,
            group.pk,
            t.message,
            t.signature,
          );
          expect(valid).toBe(t.testPassed);
        });
      }
    });
  }
});
