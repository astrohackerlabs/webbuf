import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { dirname } from "path";
import { fileURLToPath } from "url";

const NAME = "webbuf_aesgcm";
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log("Current directory:", __dirname);

const wasmPath = join(
  __dirname,
  "src",
  `rs-${NAME}-bundler`,
  `${NAME}_bg.wasm`,
);
const wasmBase64 = readFileSync(wasmPath).toString("base64");

const wasmJsCode = `
import * as ${NAME}_bg from './${NAME}_bg.js';
const wasmBase64 = "${wasmBase64}";
const wasmBinary = Uint8Array.from(atob(wasmBase64), c => c.charCodeAt(0));
const wasmModule = new WebAssembly.Module(wasmBinary);
const importObject = { './${NAME}_bg.js': ${NAME}_bg };
const wasm = new WebAssembly.Instance(wasmModule, importObject).exports;
export { wasm };
`;

const wasmJsOutputPath = join(
  __dirname,
  "src",
  `rs-${NAME}-inline-base64`,
  `${NAME}_bg.wasm.js`,
);
writeFileSync(wasmJsOutputPath, wasmJsCode);

const wasmDTsCode = `declare const wasm: string;
export { wasm };
`;

const wasmDTsOutputPath = join(
  __dirname,
  "src",
  `rs-${NAME}-inline-base64`,
  `${NAME}_bg.wasm.d.ts`,
);
writeFileSync(wasmDTsOutputPath, wasmDTsCode);

const originalFilePath = join(
  __dirname,
  "src",
  `rs-${NAME}-bundler`,
  `${NAME}.js`,
);
const originalCode = readFileSync(originalFilePath, "utf-8");

const expectedImport = `import * as wasm from "./${NAME}_bg.wasm";`;

if (!originalCode.startsWith(expectedImport)) {
  throw new Error(
    `Expected original JS file to start with '${expectedImport}'`,
  );
}

const wasmImportRegex = /import .* from ['"].*\.wasm['"];?/g;
const matches = originalCode.match(wasmImportRegex);

if (matches?.some((line) => line !== expectedImport)) {
  throw new Error(
    `Unexpected .wasm import detected:\n${matches.filter((line) => line !== expectedImport).join("\n")}`,
  );
}

const modifiedCode = originalCode.replace(
  expectedImport,
  `import { wasm } from "./${NAME}_bg.wasm.js";`,
);

const outputFilePath = join(
  __dirname,
  "src",
  `rs-${NAME}-inline-base64`,
  `${NAME}.js`,
);
writeFileSync(outputFilePath, modifiedCode);

console.log(`Modified WASM code written to ${outputFilePath}`);
