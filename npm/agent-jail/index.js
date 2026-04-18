"use strict";

// Resolve the platform-specific package that npm installed via
// optionalDependencies. One of four siblings ships the actual binary;
// the other three are silently skipped by npm's os/cpu gating.

const { platform, arch } = process;

const SUPPORTED = {
  "linux-x64": "agent-jail-linux-x64",
  "linux-arm64": "agent-jail-linux-arm64",
  "darwin-x64": "agent-jail-darwin-x64",
  "darwin-arm64": "agent-jail-darwin-arm64",
};

const key = `${platform}-${arch}`;
const pkg = SUPPORTED[key];

if (!pkg) {
  throw new Error(
    `agent-jail: unsupported platform ${key}. ` +
      `Supported: ${Object.keys(SUPPORTED).join(", ")}.`,
  );
}

let binaryPath;
try {
  binaryPath = require.resolve(`${pkg}/bin/agent-jail`);
} catch (err) {
  throw new Error(
    `agent-jail: could not locate ${pkg}/bin/agent-jail. ` +
      `npm may have skipped the optional dependency \u2014 reinstall with ` +
      `\`npm install agent-jail\` and ensure --no-optional was not set.`,
  );
}

module.exports = { path: binaryPath };
