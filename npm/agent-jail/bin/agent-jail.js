#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const os = require("node:os");
const { path } = require("../index.js");

const r = spawnSync(path, process.argv.slice(2), { stdio: "inherit" });

if (r.error) {
  process.stderr.write(`agent-jail: ${r.error.message}\n`);
  process.exit(1);
}

// Mirror POSIX exit-code convention: 128 + signal number when the child
// was signalled. os.constants.signals maps names to numbers (e.g. SIGTERM -> 15).
if (r.signal) {
  const n = os.constants.signals[r.signal];
  process.exit(128 + (typeof n === "number" ? n : 15));
}

process.exit(r.status ?? 1);
