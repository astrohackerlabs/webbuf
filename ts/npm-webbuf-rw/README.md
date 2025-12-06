# @webbuf/rw

Buffer reader and writer for sequential binary I/O.

## Installation

```bash
npm install @webbuf/rw
```

## Usage

### Writing Data

```typescript
import { BufWriter } from "@webbuf/rw";
import { U8, U16BE, U32BE, U64BE } from "@webbuf/numbers";
import { FixedBuf } from "@webbuf/fixedbuf";

const writer = new BufWriter();

// Write numbers
writer.writeU8(new U8(255));
writer.writeU16BE(new U16BE(1000));
writer.writeU32BE(new U32BE(123456));
writer.writeU64BE(new U64BE(0x123456789abcdef0n));

// Write fixed buffers
const hash = FixedBuf.fromRandom<32>(32);
writer.writeFixed(hash);

// Write variable-length data
writer.writeVarIntU64BE(new U64BE(1000n));

// Get result
const buf = writer.toBuf();
```

### Reading Data

```typescript
import { BufReader } from "@webbuf/rw";
import { WebBuf } from "@webbuf/webbuf";

const data = WebBuf.fromHex("ff03e8...");
const reader = new BufReader(data);

// Read numbers
const u8 = reader.readU8();
const u16 = reader.readU16BE();
const u32 = reader.readU32BE();
const u64 = reader.readU64BE();

// Read fixed buffers
const hash = reader.readFixed<32>(32);

// Read variable-length data
const varInt = reader.readVarIntU64BE();

// Check remaining
reader.eof();       // true if at end
reader.remainder(); // remaining bytes as WebBuf
```

## API

### BufWriter

| Method | Description |
|--------|-------------|
| `writeU8(val)` | Write 8-bit unsigned |
| `writeU16BE(val)` | Write 16-bit big-endian |
| `writeU32BE(val)` | Write 32-bit big-endian |
| `writeU64BE(val)` | Write 64-bit big-endian |
| `writeFixed(buf)` | Write fixed-size buffer |
| `writeVarIntU64BE(val)` | Write variable-length integer |
| `toBuf()` | Get result as WebBuf |

### BufReader

| Method | Description |
|--------|-------------|
| `readU8()` | Read 8-bit unsigned |
| `readU16BE()` | Read 16-bit big-endian |
| `readU32BE()` | Read 32-bit big-endian |
| `readU64BE()` | Read 64-bit big-endian |
| `readFixed<N>(size)` | Read fixed-size buffer |
| `readVarIntU64BE()` | Read variable-length integer |
| `eof()` | Check if at end |
| `remainder()` | Get remaining bytes |

## License

MIT
