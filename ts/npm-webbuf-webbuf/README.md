# @webbuf/webbuf

Extended `Uint8Array` with base64/hex encoding, optimized with Rust/WASM.

## Installation

```bash
npm install @webbuf/webbuf
```

## Usage

```typescript
import { WebBuf } from "@webbuf/webbuf";

// Create from various sources
const buf1 = WebBuf.alloc(32);
const buf2 = WebBuf.fromHex("deadbeef");
const buf3 = WebBuf.fromBase64("SGVsbG8=");
const buf4 = WebBuf.fromUtf8("Hello, world!");
const buf5 = WebBuf.fromArray([1, 2, 3, 4]);

// Convert to strings
buf2.toHex();    // "deadbeef"
buf3.toBase64(); // "SGVsbG8="
buf4.toUtf8();   // "Hello, world!"

// Buffer operations
const combined = WebBuf.concat([buf1, buf2]);
const cloned = buf1.clone();
const reversed = buf1.toReverse();

// Comparison
buf1.equals(buf2);  // false
buf1.compare(buf2); // -1, 0, or 1
```

## API

### Static Methods

| Method | Description |
|--------|-------------|
| `WebBuf.alloc(size, fill?)` | Allocate buffer of given size |
| `WebBuf.concat(list)` | Concatenate multiple buffers |
| `WebBuf.fromUint8Array(arr)` | Create from Uint8Array |
| `WebBuf.fromArray(arr)` | Create from number array |
| `WebBuf.fromHex(hex)` | Create from hex string |
| `WebBuf.fromBase64(b64)` | Create from base64 string |
| `WebBuf.fromUtf8(str)` | Create from UTF-8 string |

### Instance Methods

| Method | Description |
|--------|-------------|
| `toHex()` | Convert to hex string |
| `toBase64()` | Convert to base64 string |
| `toUtf8()` | Convert to UTF-8 string |
| `clone()` | Create a copy |
| `toReverse()` | Create reversed copy |
| `equals(other)` | Check equality |
| `compare(other)` | Compare (-1, 0, 1) |
| `slice(start?, end?)` | Get slice as WebBuf |
| `subarray(start?, end?)` | Get subarray as WebBuf |

## License

MIT
