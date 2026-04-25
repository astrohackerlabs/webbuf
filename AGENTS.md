# WebBuf - AI Agent Onboarding Guide

## Project Overview

WebBuf is a dual Rust/TypeScript monorepo providing high-performance buffer manipulation and cryptography for web environments. The core concept is:

1. Write or wrap cryptographic algorithms in **Rust**
2. Compile Rust to **WebAssembly (WASM)**
3. Inline the WASM as base64 into **TypeScript** packages
4. Publish as npm packages with the `@webbuf/` scope

The project provides a common buffer format called `WebBuf` (extends `Uint8Array`) and `FixedBuf<N>` (fixed-size buffer container, commonly 32 bytes for hashes).

## Repository Structure

```
webbuf/
├── rs/                          # Rust workspace
│   ├── Cargo.toml               # Workspace config (version: 0.12.95)
│   ├── webbuf/                  # Base64/hex encoding (core WASM)
│   ├── webbuf_blake3/           # BLAKE3 hashing
│   ├── webbuf_sha256/           # SHA-256 hashing and HMAC-SHA256
│   ├── webbuf_ripemd160/        # RIPEMD160 hashing
│   ├── webbuf_secp256k1/        # Elliptic curve cryptography
│   └── webbuf_aescbc/           # AES-CBC encryption
│
├── ts/                          # TypeScript pnpm monorepo
│   ├── package.json             # Workspace root
│   ├── pnpm-workspace.yaml      # pnpm workspace config
│   ├── eslint.config.js         # Shared ESLint config (flat config format)
│   ├── .prettierrc              # Shared Prettier config
│   ├── .prettierignore          # Prettier ignore patterns
│   ├── npm-webbuf-webbuf/       # Core WebBuf class (@webbuf/webbuf)
│   ├── npm-webbuf-fixedbuf/     # Fixed-size buffers (@webbuf/fixedbuf)
│   ├── npm-webbuf-numbers/      # U8, U16BE, U32BE, etc. (@webbuf/numbers)
│   ├── npm-webbuf-rw/           # BufReader/BufWriter (@webbuf/rw)
│   ├── npm-webbuf-blake3/       # BLAKE3 wrapper (@webbuf/blake3)
│   ├── npm-webbuf-sha256/       # SHA-256 wrapper (@webbuf/sha256)
│   ├── npm-webbuf-ripemd160/    # RIPEMD160 wrapper (@webbuf/ripemd160)
│   ├── npm-webbuf-secp256k1/    # secp256k1 wrapper (@webbuf/secp256k1)
│   ├── npm-webbuf-aescbc/       # AES-CBC wrapper (@webbuf/aescbc)
│   ├── npm-webbuf-acb3/         # Combined crypto (@webbuf/acb3)
│   ├── npm-webbuf-acb3dh/       # DH crypto (@webbuf/acb3dh)
│   └── npm-webbuf/              # Main package re-exporting all (webbuf)
│
├── issues/                      # Issue tracking (see "Issues and experiments")
├── scripts/                     # Repo-level scripts (issue index, etc.)
├── AGENTS.md                    # This file
└── CLAUDE.md                    # Symlink to AGENTS.md
```

## Languages & Tools

### Rust
- **Edition**: 2021
- **WASM Target**: `wasm32-unknown-unknown`
- **Build Tool**: `wasm-pack` (target: bundler)
- **FFI**: `wasm-bindgen 0.2`
- **Key Pattern**: Conditional WASM export via `#[cfg_attr(feature = "wasm", wasm_bindgen)]`

### TypeScript
- **Version**: 5.7.3
- **Target**: ES2022
- **Module**: ESNext (ESM only)
- **Build Tool**: Vite 6.1.0
- **Test Framework**: Vitest 3.0.5
- **Linter**: ESLint 9.x with typescript-eslint (strict type-checked rules)
- **Formatter**: Prettier 3.x (default settings)
- **Package Manager**: pnpm 9.12.3+
- **Node Version**: >=20.8.0

## Build Process: Rust to WASM to TypeScript

### Step 1: Compile Rust to WASM

Each Rust package has a `wasm-pack-bundler.zsh` script:

```bash
#!/bin/zsh
wasm-pack build --target bundler --out-dir build/bundler --release -- --features wasm
rm build/bundler/.gitignore
rm build/bundler/package.json
rm build/bundler/README.md
```

This produces in `rs/<package>/build/bundler/`:
- `<name>.js` - JavaScript bindings
- `<name>_bg.js` - Background bindings
- `<name>_bg.wasm` - Binary WASM file
- `<name>.d.ts` - TypeScript declarations

### Step 2: Copy WASM to TypeScript Package

In the TypeScript package's `package.json`:

```json
"sync:from-rust": "cp -r ../../rs/webbuf_blake3/build/bundler/* src/rs-webbuf_blake3-bundler/"
```

The bundler output is copied to `src/rs-<name>-bundler/` in the TypeScript package.

### Step 3: Inline WASM as Base64

Each TypeScript WASM package has a `build-inline-wasm.ts` script that:

1. Reads the `.wasm` binary file
2. Converts it to base64
3. Generates a JS module that instantiates WASM from the base64 string
4. Outputs to `src/rs-<name>-inline-base64/`

The inline module structure:
```javascript
import * as <name>_bg from './<name>_bg.js';
const wasmBase64 = "<base64-encoded-wasm>";
const wasmBinary = Uint8Array.from(atob(wasmBase64), c => c.charCodeAt(0));
const wasmModule = new WebAssembly.Module(wasmBinary);
const importObject = { './<name>_bg.js': <name>_bg };
const wasm = new WebAssembly.Instance(wasmModule, importObject).exports;
export { wasm };
```

**Why inline as base64?** This enables synchronous WASM loading. Normally, loading a `.wasm` file requires async operations (`fetch`, `WebAssembly.instantiateStreaming`). By inlining as base64, we can use `new WebAssembly.Module()` and `new WebAssembly.Instance()` which are synchronous. This means webbuf packages behave like normal JavaScript libraries - no async imports, no top-level await required.

### Step 4: Wrap with TypeScript

The TypeScript wrapper imports from the inline module and provides type-safe APIs:

```typescript
// Example: ts/npm-webbuf-blake3/src/index.ts
import { blake3_hash } from "./rs-webbuf_blake3-inline-base64/webbuf_blake3.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

export function blake3Hash(buf: WebBuf): FixedBuf<32> {
  const hash = blake3_hash(buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(hash));
}
```

## TypeScript Package Scripts

Each TypeScript package follows this script pattern:

```json
{
  "clean": "rimraf dist",
  "test": "vitest --run",
  "typecheck": "tsc --noEmit",
  "lint": "eslint . --fix",
  "format": "prettier --write . --ignore-path ../.prettierignore",
  "fix": "pnpm run typecheck && pnpm run lint && pnpm run format",
  "sync:from-rust": "cp -r ../../rs/<pkg>/build/bundler/* src/rs-<pkg>-bundler/",
  "build:bundler-to-inline-base64": "cp -r src/rs-<pkg>-bundler/* src/rs-<pkg>-inline-base64/",
  "build:inline-wasm": "tsx build-inline-wasm.ts",
  "build:wasm": "pnpm run build:bundler-to-inline-base64 && pnpm run build:inline-wasm",
  "build:typescript": "tsc -p tsconfig.build.json",
  "build": "pnpm run build:wasm && pnpm run build:typescript",
  "prepublishOnly": "pnpm run clean && pnpm run build"
}
```

Note: ESLint and Prettier configs are shared at the `ts/` workspace root. Each package references the root `.prettierignore` via `--ignore-path ../.prettierignore`.

## Core Types

### WebBuf

Extends `Uint8Array` with additional methods:

```typescript
class WebBuf extends Uint8Array {
  static alloc(size: number): WebBuf
  static fromUint8Array(arr: Uint8Array): WebBuf
  static fromHex(hex: string): WebBuf
  static fromBase64(b64: string): WebBuf
  static concat(bufs: WebBuf[]): WebBuf

  toHex(): string
  toBase64(): string
  clone(): WebBuf
  compare(other: WebBuf): number
  equals(other: WebBuf): boolean
}
```

### FixedBuf<N>

Type-safe fixed-size buffer wrapper:

```typescript
class FixedBuf<N extends number> {
  static alloc<N extends number>(size: N): FixedBuf<N>
  static fromBuf<N extends number>(size: N, buf: WebBuf): FixedBuf<N>
  static fromHex<N extends number>(size: N, hex: string): FixedBuf<N>
  static fromBase64<N extends number>(size: N, b64: string): FixedBuf<N>
  static fromRandom<N extends number>(size: N): FixedBuf<N>

  get buf(): WebBuf
  toHex(): string
  toBase64(): string
  clone(): FixedBuf<N>
}
```

### BufReader / BufWriter

Sequential buffer I/O with position tracking:

```typescript
class BufReader {
  constructor(buf: WebBuf)
  readU8(): U8
  readU16BE(): U16BE
  readU32BE(): U32BE
  readU64BE(): U64BE
  readFixed<N>(size: N): FixedBuf<N>
  readVarIntU64BE(): U64BE
}

class BufWriter {
  constructor()
  writeU8(val: U8): void
  writeU16BE(val: U16BE): void
  writeU32BE(val: U32BE): void
  writeU64BE(val: U64BE): void
  writeFixed<N>(buf: FixedBuf<N>): void
  toBuf(): WebBuf
}
```

## Rust Package Pattern

### Cargo.toml Template

```toml
[package]
name = "webbuf_<name>"
description = "<Description>"
version.workspace = true
edition = "2021"
license = "MIT"
authors = ["Identellica LLC"]
repository = "https://github.com/identellica/webbuf"

[lib]
crate-type = ["cdylib", "rlib"]

[features]
wasm = ["wasm-bindgen"]

[dependencies]
# ... crypto library dependencies

[dependencies.wasm-bindgen]
version = "0.2"
optional = true
```

### lib.rs Pattern

```rust
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn hash_function(data: &[u8]) -> Result<Vec<u8>, String> {
    // Implementation
    Ok(result.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        // Test with known vectors
    }
}
```

## Adding a New Crypto Package

### 1. Create Rust Package

```bash
cd rs
mkdir webbuf_<name>
```

Create files:
- `Cargo.toml` (follow template above)
- `src/lib.rs` (implement functions with `#[cfg_attr(feature = "wasm", wasm_bindgen)]`)
- `wasm-pack-bundler.zsh` (copy from existing package)
- `LICENSE` (MIT)

Add to workspace in `rs/Cargo.toml`:
```toml
[workspace]
members = [
    # ... existing members
    "webbuf_<name>",
]
```

### 2. Build WASM

```bash
cd rs/webbuf_<name>
chmod +x wasm-pack-bundler.zsh
./wasm-pack-bundler.zsh
```

### 3. Create TypeScript Package

```bash
cd ts
mkdir npm-webbuf-<name>
```

Create structure:
```
npm-webbuf-<name>/
├── package.json
├── tsconfig.json
├── tsconfig.build.json
├── vitest.config.ts
├── build-inline-wasm.ts
└── src/
    ├── index.ts
    ├── rs-webbuf_<name>-bundler/      # Will contain copied WASM
    └── rs-webbuf_<name>-inline-base64/ # Will contain inlined WASM
```

### 4. Sync and Build

```bash
cd ts/npm-webbuf-<name>
pnpm install
pnpm run sync:from-rust
pnpm run build
pnpm test
```

## Dependencies Reference

### Rust Crypto Libraries
- `blake3` - BLAKE3 hashing
- `sha2` - SHA-256 hashing (from RustCrypto)
- `hmac` - HMAC implementation (from RustCrypto, used with sha2)
- `ripemd` - RIPEMD160 hashing
- `k256` - secp256k1 elliptic curves (from RustCrypto)
- `aes` - AES encryption

### TypeScript Dev Dependencies
- `eslint` - Linting
- `@eslint/js` - ESLint core rules
- `typescript-eslint` - TypeScript ESLint plugin
- `prettier` - Code formatting
- `@types/node` - Node.js types
- `rimraf` - Cross-platform rm -rf
- `tsx` - TypeScript execution
- `typescript` - TypeScript compiler
- `vite` - Build tool
- `vitest` - Test framework

## Testing

### Rust Tests
```bash
cd rs/webbuf_<name>
cargo test
```

### TypeScript Tests
```bash
cd ts/npm-webbuf-<name>
pnpm test
```

### All TypeScript Packages
```bash
cd ts
pnpm test
```

## Publishing

NPM packages are published under the `@webbuf/` scope:
- `@webbuf/webbuf` - Core buffer
- `@webbuf/fixedbuf` - Fixed-size buffers
- `@webbuf/numbers` - Numeric types
- `@webbuf/rw` - Reader/writer
- `@webbuf/blake3` - BLAKE3 hash and MAC
- `@webbuf/sha256` - SHA-256 hash and HMAC-SHA256
- `@webbuf/ripemd160` - RIPEMD160 hash
- `@webbuf/secp256k1` - secp256k1 ECDSA and ECDH
- `@webbuf/aescbc` - AES-CBC encryption
- `@webbuf/acb3` - AES-CBC + BLAKE3 MAC
- `@webbuf/acb3dh` - AES-CBC + BLAKE3 + secp256k1 Diffie-Hellman
- `webbuf` - Main package (re-exports core utilities)

The `prepublishOnly` script ensures clean builds before publishing.

## Version Management

- **Rust workspace version**: `0.12.95` (in `rs/Cargo.toml`)
- **TypeScript version**: `3.0.28` (in each `package.json`)

Versions are managed independently but should be updated together when making releases.

## Code Style

- **Rust**: Standard Rust formatting (`cargo fmt`)
- **TypeScript**: ESLint with strict type-checked rules + Prettier with default settings
- **No emojis** unless explicitly requested
- **Strict TypeScript** mode enabled
- **ESM only** - no CommonJS

## Issues and experiments

Every significant piece of work gets an issue in `issues/`. Issues describe the
problem, provide background, and propose solutions. Experiments are the
incremental steps that solve the problem.

### Issue structure

Each issue is a **folder** containing a `README.md` with TOML frontmatter:

```
issues/0001-some-topic/
├── README.md          <- main issue document with frontmatter
├── 01-sub-topic.md    <- optional: additional files for long issues
└── 02-sub-topic.md
```

The folder name is `{number}-{slug}`. The number is 4-digit, globally
sequential.

#### Frontmatter

```
+++
status = "open"
opened = "2026-04-25"
+++
```

When closing, add `closed = "YYYY-MM-DD"` and change `status` to `"closed"`.

### Experiments

Only after the issue's requirements are clear. Each experiment is designed,
implemented, and concluded before the next one is designed.

**Never list experiments upfront.** The outcome of each experiment informs what
comes next.

### Process summary

1. Create the issue with frontmatter, goal, background. No experiments yet.
2. Design Experiment 1.
3. Implement Experiment 1.
4. Record the result — Pass, partial, or fail with a conclusion.
5. Repeat until the goal is met.
6. Close the issue — write a Conclusion section, update frontmatter.

Every closed issue MUST have a `## Conclusion` section summarizing what was
accomplished, what changed, and key decisions made. The conclusion is the
permanent record of the work — someone reading only the conclusion should
understand the outcome without reading every experiment.

Closed issues are immutable and must NEVER be modified.

### Index

`issues/README.md` is generated by `scripts/build-issues-index.sh`. Run it after
opening, closing, or renaming any issue. The script parses TOML frontmatter,
extracts the H1 title, and rebuilds Open and Closed tables.
