# agent-jail

Portable filesystem sandbox for spawning untrusted subprocesses. One
static binary, picks the strongest backend available at runtime: uid
switch on POSIX, Landlock on Linux 5.13+, or both layered.

Full docs: https://github.com/Michaelliv/agent-jail

## Install

```sh
npm install agent-jail
```

This installs the platform-specific binary via `optionalDependencies`.
One of `agent-jail-linux-x64`, `agent-jail-linux-arm64`,
`agent-jail-darwin-x64`, `agent-jail-darwin-arm64` will be installed;
the rest are skipped by npm's `os`/`cpu` gating.

## Use from Node

```js
import { path } from "agent-jail";
import { spawn } from "node:child_process";

spawn(path, [
  "--best-effort",
  "--system-ro",
  "--rw", workspace,
  "--hide", secrets,
  "--", "my-agent",
], { stdio: "inherit" });
```

## Use as a CLI

```sh
npx agent-jail --version
npx agent-jail --best-effort --system-ro --rw /tmp/work -- /usr/bin/true
```

## License

MIT.
