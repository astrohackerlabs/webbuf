# @webbuf/fixedbuf

Fixed-size buffer wrapper with compile-time size enforcement.

## Installation

```bash
npm install @webbuf/fixedbuf
```

## Usage

```typescript
import { FixedBuf } from "@webbuf/fixedbuf";
import { WebBuf } from "@webbuf/webbuf";

// Create fixed-size buffers
const buf32 = FixedBuf.alloc<32>(32); // 32-byte buffer
const buf16 = FixedBuf.alloc<16>(16, 0xff); // 16 bytes filled with 0xff
const random = FixedBuf.fromRandom<32>(32); // 32 random bytes

// Create from encoded strings
const fromHex = FixedBuf.fromHex<4>(4, "deadbeef");
const fromB64 = FixedBuf.fromBase64(16, "SGVsbG8gV29ybGQhISE=");

// Create from WebBuf
const webBuf = WebBuf.alloc(32);
const fixed = FixedBuf.fromBuf<32>(32, webBuf);

// Access underlying buffer
const underlying: WebBuf = fixed.buf;

// Convert to strings
fromHex.toHex(); // "deadbeef"
fromB64.toBase64(); // "SGVsbG8gV29ybGQhISE="

// Clone and reverse
const cloned = fixed.clone();
const reversed = fixed.toReverse();
```

## API

### Static Methods

| Method                           | Description                |
| -------------------------------- | -------------------------- |
| `FixedBuf.alloc<N>(size, fill?)` | Allocate fixed-size buffer |
| `FixedBuf.fromBuf<N>(size, buf)` | Create from WebBuf         |
| `FixedBuf.fromHex<N>(size, hex)` | Create from hex string     |
| `FixedBuf.fromBase64(size, b64)` | Create from base64 string  |
| `FixedBuf.fromRandom<N>(size)`   | Create with random bytes   |

### Instance Properties/Methods

| Property/Method | Description              |
| --------------- | ------------------------ |
| `buf`           | Get underlying WebBuf    |
| `toHex()`       | Convert to hex string    |
| `toBase64()`    | Convert to base64 string |
| `clone()`       | Create a copy            |
| `toReverse()`   | Create reversed copy     |

## License

MIT
