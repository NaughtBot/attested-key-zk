# @naughtbot/attested-key-zk-wasm

TypeScript wrapper around the Emscripten build of `attested-key-zk`.

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm build:wasm
pnpm build
pnpm smoke
```

The generated `dist/` and `lib/` directories are packaged for releases but are
not committed to git.

## WASM memory model

The TypeScript wrapper assumes the underlying Emscripten module is `wasm32`
(32-bit pointers). `scripts/build-wasm.sh` does **not** pass `-sMEMORY64`,
so the assumption holds today.

If `-sMEMORY64` is ever enabled, the pointer-sized allocations in
`src/index.ts` must be bumped from 4 to 8 bytes:

- `_malloc(4)` for the prover output-pointer slots in `generateCircuit`
  (`outPtrPtr`, `outLenPtr`) and `prove` (`outPtrPtr`, `outLenPtr`).
- The 32-byte buffer in `circuitID` is digest-sized, not pointer-sized,
  so it stays at 32 regardless of memory model.

A `-sMEMORY64` build also requires checking the `getValue("*", ...)` and
`getValue(_, "i32")` calls in `index.ts`, which read pointers / 32-bit
sizes out of WASM memory and would need updates to read 64-bit slots.

This is documented for future maintainers; no action required as long as
the build script keeps wasm32.
