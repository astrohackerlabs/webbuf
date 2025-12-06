# @webbuf/numbers

Fixed-size unsigned integers with big-endian and little-endian support.

## Installation

```bash
npm install @webbuf/numbers
```

## Usage

```typescript
import {
  U8,
  U16BE,
  U16LE,
  U32BE,
  U32LE,
  U64BE,
  U64LE,
  U128BE,
  U128LE,
  U256BE,
  U256LE,
} from "@webbuf/numbers";

// Create from number or bigint
const a = U32BE.fromN(1000);
const b = U64BE.fromBn(0x123456789abcdef0n);

// Arithmetic
const sum = a.add(U32BE.fromN(500));
const diff = a.sub(U32BE.fromN(100));
const product = a.mul(U32BE.fromN(2));
const quotient = a.div(U32BE.fromN(10));

// Convert to number/bigint
a.n; // 1000 (number)
a.bn; // 1000n (bigint)

// Buffer conversions
const beBuf = a.toBEBuf(); // Big-endian FixedBuf
const leBuf = a.toLEBuf(); // Little-endian FixedBuf
const restored = U32BE.fromBEBuf(beBuf);

// Hex conversions
const hex = a.toHex(); // "000003e8"
const fromHex = U32BE.fromHex("000003e8");
```

## Types

| Type               | Size     | Range              |
| ------------------ | -------- | ------------------ |
| `U8`               | 1 byte   | 0 to 255           |
| `U16BE`, `U16LE`   | 2 bytes  | 0 to 65,535        |
| `U32BE`, `U32LE`   | 4 bytes  | 0 to 4,294,967,295 |
| `U64BE`, `U64LE`   | 8 bytes  | 0 to 2^64-1        |
| `U128BE`, `U128LE` | 16 bytes | 0 to 2^128-1       |
| `U256BE`, `U256LE` | 32 bytes | 0 to 2^256-1       |

`BE` = Big Endian, `LE` = Little Endian

## API

### Static Methods

| Method           | Description                      |
| ---------------- | -------------------------------- |
| `fromN(n)`       | Create from number               |
| `fromBn(bn)`     | Create from bigint               |
| `fromBEBuf(buf)` | Create from big-endian buffer    |
| `fromLEBuf(buf)` | Create from little-endian buffer |
| `fromHex(hex)`   | Create from hex string           |

### Instance Properties/Methods

| Property/Method | Description                     |
| --------------- | ------------------------------- |
| `n`             | Get value as number             |
| `bn`            | Get value as bigint             |
| `add(other)`    | Add                             |
| `sub(other)`    | Subtract                        |
| `mul(other)`    | Multiply                        |
| `div(other)`    | Divide                          |
| `toBEBuf()`     | Convert to big-endian buffer    |
| `toLEBuf()`     | Convert to little-endian buffer |
| `toHex()`       | Convert to hex string           |

## License

MIT
