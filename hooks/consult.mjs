import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const raw = readFileSync(0, "utf8");
let input = {};
if (raw.trim()) {
  try {
    input = JSON.parse(raw);
  } catch {
    input = {};
  }
}

if (process.env.CLOSEOUT_HOOK === "0" || input.stop_hook_active === true) {
  process.exit(0);
}

const root = typeof input.cwd === "string" && input.cwd.length > 0 ? input.cwd : process.cwd();

const event = input.hook_event_name || input.hookEventName || "";

function finish(reason) {
  if (event === "TaskCompleted") {
    process.stderr.write(`${reason}\n`);
    process.exit(2);
  }
  process.stdout.write(`${JSON.stringify({ decision: "block", reason })}\n`);
  process.exit(0);
}

function gitRev(rev) {
  const result = spawnSync(
    "git",
    ["-C", root, "rev-parse", "--verify", "--end-of-options", `${rev}^{commit}`],
    { encoding: "utf8" },
  );
  if (result.status !== 0) return "";
  return result.stdout.trim();
}

const head = gitRev("HEAD");
const base = process.env.CLOSEOUT_BASE ? gitRev(process.env.CLOSEOUT_BASE) : head;
if (!head || !base) {
  finish("base or head does not resolve to a commit");
}

const bin = process.env.CLOSEOUT_BIN || "closeout";
const args = ["decision", "--gate", "beforePR", "--base", base, "--head", head, "--root", root, "--json"];
if (process.env.CLOSEOUT_TASK) args.push("--task", process.env.CLOSEOUT_TASK);
const session = input.session_id || input.sessionId || "";
if (session) args.push("--candidate-session", String(session));
if (typeof input.model === "string" && input.model.length > 0) args.push("--candidate-model", input.model);

const result = spawnSync(bin, args, { encoding: "utf8", cwd: root });
let decision = null;
if (result.stdout && result.stdout.trim()) {
  try {
    decision = JSON.parse(result.stdout);
  } catch {
    decision = null;
  }
}
if (!decision || typeof decision.decision !== "string") {
  if (result.error || result.status === null) finish("closeout runner is not available");
  finish((result.stderr || "closeout decision did not return JSON").trim());
}
if (decision.decision === "accepted") process.exit(0);

const lines = [`closeout ${decision.decision} beforePR`];
if (decision.message) lines.push(decision.message);
for (const item of decision.items || []) {
  if (item.state === "skipped") continue;
  lines.push(`${item.id}  ${item.state}  ${item.message}`);
}
const reason = lines.join("\n");
if (event !== "TaskCompleted" && (decision.items || []).some((item) => item.state === "exhausted")) {
  process.stdout.write(`${JSON.stringify({ systemMessage: reason })}\n`);
  process.exit(0);
}
finish(reason);
