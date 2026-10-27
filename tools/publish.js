#!/usr/bin/env node
// publish — encrypt every page in src/ into docs/ (GitHub Pages). src/ and config/ never leave this machine.
"use strict";
const fs = require("fs"), path = require("path"); const { gate } = require("./gate");
const ROOT = path.join(__dirname, ".."), SRC = path.join(ROOT, "src"), OUT = path.join(ROOT, "docs");
function walk(d) { return fs.readdirSync(d, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(path.join(d, e.name)) : (e.name.endsWith(".html") ? [path.join(d, e.name)] : [])); }
const pages = walk(SRC);
for (const out of fs.existsSync(OUT) ? walk(OUT) : []) if (!fs.existsSync(path.join(SRC, path.relative(OUT, out)))) fs.unlinkSync(out);
for (const src of pages) { const out = path.join(OUT, path.relative(SRC, src)); fs.mkdirSync(path.dirname(out), { recursive: true }); fs.writeFileSync(out, gate(fs.readFileSync(src, "utf8"))); }
fs.writeFileSync(path.join(OUT, ".nojekyll"), "");
console.log(`encrypted ${pages.length} page(s) into docs/`);
