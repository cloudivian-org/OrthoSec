import { execSync } from "child_process";

export function deploy(cmd: string): string {
  return execSync(cmd).toString();
}
