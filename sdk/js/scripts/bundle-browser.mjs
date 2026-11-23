#!/usr/bin/env node
// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Bundles an ES module for a browser page with esbuild, the way a page's own
// bundler would: package.json "browser" fields swap the Node platform files
// for their browser twins, and a .wasm import (biscuit-wasm is built for
// bundlers and imports its module that way) becomes a module that fetches
// the file beside the bundle and instantiates it. Bundling dist/index.js
// this way also proves that nothing in the browser graph reaches for Node.
//
//   node scripts/bundle-browser.mjs [entry] [outdir] [--minify] [--no-sourcemap]
//
// Defaults: dist/index.js into build/browser, unminified, with a source map.

import * as esbuild from "esbuild";
import { readFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith("--")));
const [entry = join(here, "..", "dist", "index.js"), outdir = join(here, "..", "build", "browser")] = args.filter((a) => !a.startsWith("--"));

/** import * as wasm from "./x.wasm" as WebAssembly ESM integration would resolve it. */
const wasmModules = {
  name: "wasm-esm",
  setup(build) {
    build.onResolve({ filter: /\.wasm$/ }, (args) => ({ path: join(args.resolveDir, args.path), namespace: "wasm-esm" }));
    build.onLoad({ filter: /.*/, namespace: "wasm-esm" }, async (args) => {
      const bytes = await readFile(args.path);
      const module = new WebAssembly.Module(bytes);
      const importModules = [...new Set(WebAssembly.Module.imports(module).map((imp) => imp.module))];
      const exports = WebAssembly.Module.exports(module).map((exp) => exp.name);
      const lines = [];
      const imports = [];
      importModules.forEach((mod, i) => {
        if (mod.startsWith("./") || mod.startsWith("../")) {
          lines.push(`import * as m${i} from ${JSON.stringify(mod)};`);
          imports.push(`${JSON.stringify(mod)}: m${i}`);
        } else {
          // wasm-bindgen's own placeholder module: intrinsics the bindings provide by name.
          imports.push(`${JSON.stringify(mod)}: { performance_now: () => performance.now() }`);
        }
      });
      lines.push(`const url = new URL(${JSON.stringify(basename(args.path))}, import.meta.url);`);
      lines.push(`const { instance } = await WebAssembly.instantiateStreaming(fetch(url), { ${imports.join(", ")} });`);
      for (const name of exports) {
        lines.push(`export const ${name} = instance.exports[${JSON.stringify(name)}];`);
      }
      return { contents: lines.join("\n"), loader: "js", resolveDir: dirname(args.path), watchFiles: [args.path] };
    });
    // The .wasm file itself goes beside the bundle under its own name.
    build.onResolve({ filter: /\.wasm$/, namespace: "wasm-esm" }, (args) => ({ path: args.path, namespace: "wasm-file" }));
  },
};

const result = await esbuild.build({
  entryPoints: [entry],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  outdir,
  entryNames: "[name]",
  assetNames: "[name]",
  sourcemap: !flags.has("--no-sourcemap"),
  minify: flags.has("--minify"),
  plugins: [wasmModules],
  metafile: true,
  logLevel: "warning",
});

// The bytes the stub fetches: copy every .wasm the graph touched beside the bundle.
const { copyFile, mkdir, readdir } = await import("node:fs/promises");
await mkdir(outdir, { recursive: true });
for (const input of Object.keys(result.metafile.inputs)) {
  if (input.startsWith("wasm-esm:")) {
    const file = input.slice("wasm-esm:".length);
    await copyFile(file, join(outdir, basename(file)));
  }
}
// A page's static files beside the entry (index.html) go with it.
for (const name of await readdir(dirname(entry))) {
  if (name.endsWith(".html") || name.endsWith(".css")) {
    await copyFile(join(dirname(entry), name), join(outdir, name));
  }
}
const nodeBuiltins = Object.keys(result.metafile.inputs).filter((p) => p.startsWith("node:"));
if (nodeBuiltins.length > 0) {
  console.error(`browser bundle reaches Node: ${nodeBuiltins.join(", ")}`);
  process.exit(1);
}
console.log(`bundled ${entry} into ${outdir}`);
