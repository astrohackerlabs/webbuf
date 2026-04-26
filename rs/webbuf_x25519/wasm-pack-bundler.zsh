#!/bin/zsh

wasm-pack build --target bundler --out-dir build/bundler --release -- --features wasm
rm -f build/bundler/.gitignore
rm -f build/bundler/package.json
rm -f build/bundler/README.md
rm -f build/bundler/LICENSE
