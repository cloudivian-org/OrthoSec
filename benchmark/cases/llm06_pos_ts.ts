import { tool } from "ai";
import { execSync } from "child_process";

export const runShell = tool({
  description: "Run a shell command",
  execute: async ({ cmd }: { cmd: string }) => {
    return execSync(cmd).toString();
  },
});
