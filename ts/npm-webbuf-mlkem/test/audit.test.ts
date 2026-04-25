/**
 * Audit tests for @webbuf/mlkem
 *
 * Validates the implementation against official NIST ACVP test vectors
 * for FIPS 203 (ML-KEM). See test/vectors/README.md for sources.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import {
  ML_KEM_512,
  ML_KEM_768,
  ML_KEM_1024,
  mlKem512KeyPair,
  mlKem512Encapsulate,
  mlKem512Decapsulate,
  mlKem768KeyPair,
  mlKem768Encapsulate,
  mlKem768Decapsulate,
  mlKem1024KeyPair,
  mlKem1024Encapsulate,
  mlKem1024Decapsulate,
} from "../src/index.js";
import { FixedBuf } from "@webbuf/fixedbuf";

const __dirname = dirname(fileURLToPath(import.meta.url));

interface KeyGenTest {
  tcId: number;
  z: string;
  d: string;
  ek: string;
  dk: string;
}

interface EncapTest {
  tcId: number;
  ek: string;
  m: string;
  c: string;
  k: string;
}

interface DecapTest {
  tcId: number;
  c: string;
  k: string;
}

interface KeyGenGroup {
  parameterSet: "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024";
  tests: KeyGenTest[];
}

interface EncapGroup {
  parameterSet: "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024";
  function: "encapsulation";
  tests: EncapTest[];
}

interface DecapGroup {
  parameterSet: "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024";
  function: "decapsulation";
  dk: string;
  ek: string;
  tests: DecapTest[];
}

const keygenVectors = JSON.parse(
  readFileSync(join(__dirname, "vectors", "keygen.json"), "utf-8"),
) as { testGroups: KeyGenGroup[] };

const encapDecapVectors = JSON.parse(
  readFileSync(join(__dirname, "vectors", "encap-decap.json"), "utf-8"),
) as { testGroups: (EncapGroup | DecapGroup)[] };

type ParamSetSizes = {
  ek: number;
  dk: number;
  ct: number;
};

const PARAMS: Record<KeyGenGroup["parameterSet"], ParamSetSizes> = {
  "ML-KEM-512": {
    ek: ML_KEM_512.encapsulationKeySize,
    dk: ML_KEM_512.decapsulationKeySize,
    ct: ML_KEM_512.ciphertextSize,
  },
  "ML-KEM-768": {
    ek: ML_KEM_768.encapsulationKeySize,
    dk: ML_KEM_768.decapsulationKeySize,
    ct: ML_KEM_768.ciphertextSize,
  },
  "ML-KEM-1024": {
    ek: ML_KEM_1024.encapsulationKeySize,
    dk: ML_KEM_1024.decapsulationKeySize,
    ct: ML_KEM_1024.ciphertextSize,
  },
};

function runKeyGen(
  param: KeyGenGroup["parameterSet"],
  d: FixedBuf<32>,
  z: FixedBuf<32>,
): { ek: string; dk: string } {
  switch (param) {
    case "ML-KEM-512": {
      const kp = mlKem512KeyPair(d, z);
      return {
        ek: kp.encapsulationKey.toHex(),
        dk: kp.decapsulationKey.toHex(),
      };
    }
    case "ML-KEM-768": {
      const kp = mlKem768KeyPair(d, z);
      return {
        ek: kp.encapsulationKey.toHex(),
        dk: kp.decapsulationKey.toHex(),
      };
    }
    case "ML-KEM-1024": {
      const kp = mlKem1024KeyPair(d, z);
      return {
        ek: kp.encapsulationKey.toHex(),
        dk: kp.decapsulationKey.toHex(),
      };
    }
  }
}

function runEncap(
  param: EncapGroup["parameterSet"],
  ek: string,
  m: FixedBuf<32>,
): { c: string; k: string } {
  const sizes = PARAMS[param];
  const ekBuf = FixedBuf.fromHex(sizes.ek as 800, ek);
  switch (param) {
    case "ML-KEM-512": {
      const r = mlKem512Encapsulate(ekBuf as FixedBuf<800>, m);
      return { c: r.ciphertext.toHex(), k: r.sharedSecret.toHex() };
    }
    case "ML-KEM-768": {
      const r = mlKem768Encapsulate(
        FixedBuf.fromHex(1184, ek) as FixedBuf<1184>,
        m,
      );
      return { c: r.ciphertext.toHex(), k: r.sharedSecret.toHex() };
    }
    case "ML-KEM-1024": {
      const r = mlKem1024Encapsulate(
        FixedBuf.fromHex(1568, ek) as FixedBuf<1568>,
        m,
      );
      return { c: r.ciphertext.toHex(), k: r.sharedSecret.toHex() };
    }
  }
}

function runDecap(
  param: DecapGroup["parameterSet"],
  dk: string,
  c: string,
): string {
  switch (param) {
    case "ML-KEM-512": {
      return mlKem512Decapsulate(
        FixedBuf.fromHex(1632, dk) as FixedBuf<1632>,
        FixedBuf.fromHex(768, c) as FixedBuf<768>,
      ).toHex();
    }
    case "ML-KEM-768": {
      return mlKem768Decapsulate(
        FixedBuf.fromHex(2400, dk) as FixedBuf<2400>,
        FixedBuf.fromHex(1088, c) as FixedBuf<1088>,
      ).toHex();
    }
    case "ML-KEM-1024": {
      return mlKem1024Decapsulate(
        FixedBuf.fromHex(3168, dk) as FixedBuf<3168>,
        FixedBuf.fromHex(1568, c) as FixedBuf<1568>,
      ).toHex();
    }
  }
}

describe("Audit: NIST ACVP keyGen test vectors (FIPS 203)", () => {
  for (const group of keygenVectors.testGroups) {
    describe(group.parameterSet, () => {
      for (const t of group.tests) {
        it(`tcId ${String(t.tcId)}: deterministic keygen matches expected ek and dk`, () => {
          const d = FixedBuf.fromHex(32, t.d);
          const z = FixedBuf.fromHex(32, t.z);
          const out = runKeyGen(group.parameterSet, d, z);
          expect(out.ek.toLowerCase()).toBe(t.ek.toLowerCase());
          expect(out.dk.toLowerCase()).toBe(t.dk.toLowerCase());
        });
      }
    });
  }
});

describe("Audit: NIST ACVP encapsulation test vectors (FIPS 203)", () => {
  for (const group of encapDecapVectors.testGroups) {
    if (group.function !== "encapsulation") continue;
    const encapGroup = group;
    describe(encapGroup.parameterSet, () => {
      for (const t of encapGroup.tests) {
        it(`tcId ${String(t.tcId)}: deterministic encapsulate matches expected ciphertext and shared secret`, () => {
          const m = FixedBuf.fromHex(32, t.m);
          const out = runEncap(encapGroup.parameterSet, t.ek, m);
          expect(out.c.toLowerCase()).toBe(t.c.toLowerCase());
          expect(out.k.toLowerCase()).toBe(t.k.toLowerCase());
        });
      }
    });
  }
});

describe("Audit: NIST ACVP decapsulation test vectors (FIPS 203)", () => {
  for (const group of encapDecapVectors.testGroups) {
    if (group.function !== "decapsulation") continue;
    const decapGroup = group;
    describe(decapGroup.parameterSet, () => {
      for (const t of decapGroup.tests) {
        it(`tcId ${String(t.tcId)}: decapsulate produces expected shared secret`, () => {
          const k = runDecap(decapGroup.parameterSet, decapGroup.dk, t.c);
          expect(k.toLowerCase()).toBe(t.k.toLowerCase());
        });
      }
    });
  }
});
