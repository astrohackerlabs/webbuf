# @webbuf/ripemd160

RIPEMD-160 cryptographic hash, optimized with Rust/WASM.

## Installation

```bash
npm install @webbuf/ripemd160
```

## Usage

```typescript
import { ripemd160Hash, doubleRipemd160Hash } from "@webbuf/ripemd160";
import { WebBuf } from "@webbuf/webbuf";

// RIPEMD-160 hash
const data = WebBuf.fromUtf8("Hello, world!");
const hash = ripemd160Hash(data);
console.log(hash.toHex()); // 20-byte hash

// Double hash (hash of hash)
const doubleHash = doubleRipemd160Hash(data);
```

## API

| Function                                          | Description             |
| ------------------------------------------------- | ----------------------- |
| `ripemd160Hash(data: WebBuf): FixedBuf<20>`       | Compute RIPEMD-160 hash |
| `doubleRipemd160Hash(data: WebBuf): FixedBuf<20>` | Compute hash of hash    |

## License

MIT
