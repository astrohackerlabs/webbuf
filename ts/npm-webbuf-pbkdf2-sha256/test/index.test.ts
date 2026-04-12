import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { pbkdf2Sha256 } from "../src/index.js";

describe("pbkdf2Sha256", () => {
  it("should derive a key of the requested length", () => {
    const password = WebBuf.fromUtf8("password");
    const salt = WebBuf.fromUtf8("salt");
    const result = pbkdf2Sha256(password, salt, 1, 32);
    expect(result.buf.length).toBe(32);
  });

  it("should be deterministic", () => {
    const password = WebBuf.fromUtf8("password");
    const salt = WebBuf.fromUtf8("salt");
    const result1 = pbkdf2Sha256(password, salt, 100, 32);
    const result2 = pbkdf2Sha256(password, salt, 100, 32);
    expect(result1.toHex()).toBe(result2.toHex());
  });

  it("should produce different output for different passwords", () => {
    const salt = WebBuf.fromUtf8("salt");
    const result1 = pbkdf2Sha256(WebBuf.fromUtf8("password1"), salt, 1, 32);
    const result2 = pbkdf2Sha256(WebBuf.fromUtf8("password2"), salt, 1, 32);
    expect(result1.toHex()).not.toBe(result2.toHex());
  });
});
