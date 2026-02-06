import { describe, it, expect } from "vitest";
import {
  blake3Hash,
  doubleBlake3Hash,
  blake3Mac,
  Blake3Hasher,
  createBlake3Hasher,
  createBlake3KeyedHasher,
} from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

describe("Blake3", () => {
  it("should correctly compute blake3 hash", () => {
    const input = WebBuf.fromUtf8("test input");
    const result = blake3Hash(input);

    expect(result).toBeInstanceOf(FixedBuf);
    expect(result.buf.length).toBe(32);
    const expectedHashHex =
      "aa4909e14f1389afc428e481ea20ffd9673604711f5afb60a747fec57e4c267c";
    expect(result.toHex()).toBe(expectedHashHex);
  });

  it("should correctly compute double blake3 hash", () => {
    const input = WebBuf.fromUtf8("test input");
    const result = doubleBlake3Hash(input);

    expect(result).toBeInstanceOf(FixedBuf);
    expect(result.buf.length).toBe(32);
    const expectedDoubleHashHex =
      "f89701be8691e987be5dfc6af49073c1d3faf76fdaa8ae71221f73d7cb2cea60";
    expect(result.toHex()).toBe(expectedDoubleHashHex);
  });

  it("should correctly compute blake3 MAC", () => {
    const key = blake3Hash(WebBuf.fromUtf8("key"));
    const message = WebBuf.fromUtf8("message");
    const result = blake3Mac(key, message);

    expect(result).toBeInstanceOf(FixedBuf);
    expect(result.buf.length).toBe(32);
    const expectedMacHex =
      "55603656ac7bd780db8fece23aad002ee008a605540fe3527a260c4b6e3b2b7e";
    expect(result.toHex()).toBe(expectedMacHex);
  });
});

describe("Blake3Hasher (incremental/streaming)", () => {
  it("should produce the same hash as one-shot blake3Hash", () => {
    const input = WebBuf.fromUtf8("test input");
    const expected = blake3Hash(input);

    const hasher = new Blake3Hasher();
    hasher.update(input);
    const result = hasher.finalize();
    hasher.dispose();

    expect(result.toHex()).toBe(expected.toHex());
  });

  it("should produce correct hash when data is fed in chunks", () => {
    const fullData = WebBuf.fromUtf8("hello world this is a streaming test");
    const expected = blake3Hash(fullData);

    const hasher = createBlake3Hasher();
    hasher.update(WebBuf.fromUtf8("hello world "));
    hasher.update(WebBuf.fromUtf8("this is a "));
    hasher.update(WebBuf.fromUtf8("streaming test"));
    const result = hasher.finalize();
    hasher.dispose();

    expect(result.toHex()).toBe(expected.toHex());
  });

  it("should support method chaining on update", () => {
    const fullData = WebBuf.fromUtf8("abcdef");
    const expected = blake3Hash(fullData);

    const hasher = createBlake3Hasher();
    const result = hasher
      .update(WebBuf.fromUtf8("ab"))
      .update(WebBuf.fromUtf8("cd"))
      .update(WebBuf.fromUtf8("ef"))
      .finalize();
    hasher.dispose();

    expect(result.toHex()).toBe(expected.toHex());
  });

  it("should support reset for reuse", () => {
    const hasher = createBlake3Hasher();

    // Hash some data
    hasher.update(WebBuf.fromUtf8("garbage data"));

    // Reset and hash new data
    hasher.reset();
    hasher.update(WebBuf.fromUtf8("test input"));
    const result = hasher.finalize();
    hasher.dispose();

    const expected = blake3Hash(WebBuf.fromUtf8("test input"));
    expect(result.toHex()).toBe(expected.toHex());
  });

  it("should support keyed hasher (MAC) in streaming mode", () => {
    const key = blake3Hash(WebBuf.fromUtf8("key"));
    const message = WebBuf.fromUtf8("message");
    const expected = blake3Mac(key, message);

    const hasher = createBlake3KeyedHasher(key);
    hasher.update(WebBuf.fromUtf8("mes"));
    hasher.update(WebBuf.fromUtf8("sage"));
    const result = hasher.finalize();
    hasher.dispose();

    expect(result.toHex()).toBe(expected.toHex());
  });

  it("should support static newKeyed factory", () => {
    const key = blake3Hash(WebBuf.fromUtf8("key"));
    const message = WebBuf.fromUtf8("message");
    const expected = blake3Mac(key, message);

    const hasher = Blake3Hasher.newKeyed(key);
    hasher.update(message);
    const result = hasher.finalize();
    hasher.dispose();

    expect(result.toHex()).toBe(expected.toHex());
  });

  it("should allow finalize without consuming (can continue updating)", () => {
    const hasher = createBlake3Hasher();
    hasher.update(WebBuf.fromUtf8("part1"));
    const hash1 = hasher.finalize();

    // Continue feeding data after finalize
    hasher.update(WebBuf.fromUtf8("part2"));
    const hash2 = hasher.finalize();
    hasher.dispose();

    // hash1 should equal blake3Hash("part1")
    expect(hash1.toHex()).toBe(blake3Hash(WebBuf.fromUtf8("part1")).toHex());

    // hash2 should equal blake3Hash("part1part2")
    expect(hash2.toHex()).toBe(
      blake3Hash(WebBuf.fromUtf8("part1part2")).toHex(),
    );
  });

  it("should support Symbol.dispose", () => {
    const hasher = createBlake3Hasher();
    hasher.update(WebBuf.fromUtf8("test"));
    hasher.finalize();
    // Should not throw
    hasher[Symbol.dispose]();
  });
});
