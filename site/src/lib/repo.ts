import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export function repoFile(path: string): string {
  return readFileSync(fileURLToPath(new URL(`../../../${path}`, import.meta.url)), "utf8");
}
