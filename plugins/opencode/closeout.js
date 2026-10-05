import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const NOTE =
  "The runner reads .agents/closeout.yaml from origin/main. If that commit has no policy, Closeout adds no requirements. A file in the work tree does not change the policy. Run closeout decision --gate beforePR --base <base> --head <head> --json. Exit 0 means accepted. This session stopping does not accept the work and does not permit opening a pull request.";

export const Closeout = async ({ directory, client }) => {
  return {
    "experimental.chat.system.transform": async (_input, output) => {
      try {
        if (output && Array.isArray(output.system)) output.system.push(NOTE);
      } catch {
        return;
      }
    },
    event: async ({ event }) => {
      try {
        await nudge(directory, client, event);
      } catch {
        return;
      }
    },
  };
};

async function nudge(directory, client, event) {
  if (!event || event.type !== "session.idle") return;
  const root = directory || process.cwd();
  const head = rev(root, "HEAD");
  if (!head) return;
  const base = process.env.CLOSEOUT_BASE ? rev(root, process.env.CLOSEOUT_BASE) : head;
  if (!base) return;
  const path = join(root, ".closeout", "hook-nudges.json");
  const counts = readCounts(path);
  if ((counts[head] || 0) >= 3) return;
  const bin = process.env.CLOSEOUT_BIN || "closeout";
  const result = spawnSync(
    bin,
    ["decision", "--gate", "beforePR", "--base", base, "--head", head, "--root", root, "--json"],
    { encoding: "utf8", cwd: root },
  );
  let decision = null;
  try {
    decision = JSON.parse(result.stdout);
  } catch {
    return;
  }
  if (!decision || decision.decision === "accepted") return;
  const sessionID = event.properties && event.properties.sessionID;
  if (!sessionID || !client || !client.session || typeof client.session.prompt !== "function") return;
  counts[head] = (counts[head] || 0) + 1;
  writeCounts(path, counts);
  await client.session.prompt({
    path: { id: sessionID },
    body: { parts: [{ type: "text", text: reason(decision) }] },
  });
}

function reason(decision) {
  const lines = [`closeout ${decision.decision} beforePR`];
  if (decision.message) lines.push(decision.message);
  for (const item of decision.items || []) {
    if (item.state === "skipped") continue;
    lines.push(`${item.id}  ${item.state}  ${item.message}`);
  }
  return lines.join("\n");
}

function readCounts(path) {
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function writeCounts(path, counts) {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, `${JSON.stringify(counts)}\n`);
}

function rev(root, name) {
  const result = spawnSync(
    "git",
    ["-C", root, "rev-parse", "--verify", "--end-of-options", `${name}^{commit}`],
    { encoding: "utf8" },
  );
  if (result.status !== 0) return "";
  return result.stdout.trim();
}
