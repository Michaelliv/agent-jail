#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const { path } = require("../index.js");

const r = spawnSync(path, process.argv.slice(2), { stdio: "inherit" });
if (r.error) {
  process.stderr.write(`agent-jail: ${r.error.message}\n`);
  process.exit(1);
}
process.exit(r.status ?? (r.signal ? 128 + 15 : 1));
