/**
 * Absolute path to the agent-jail binary matching the current platform.
 *
 * @example
 * import { path } from "agent-jail";
 * import { spawn } from "node:child_process";
 * spawn(path, ["--best-effort", "--system-ro", "--rw", workspace, "--", cmd]);
 */
export const path: string;
