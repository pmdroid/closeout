import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const { Closeout } = await import(pathToFileURL(process.env.PLUGIN).href);
const root = process.env.ROOT;
const mode = process.env.MODE;
const prompts = [];
const client = {
  session: {
    prompt: async (body) => {
      prompts.push(body);
      if (process.env.PROMPT_THROWS === "1") throw new Error("prompt failed");
    },
  },
};
const plugin = await Closeout({ directory: root, client });

if (mode === "system") {
  const output = { system: ["existing"] };
  await plugin["experimental.chat.system.transform"]({}, output);
  if (output.system.length !== 2) process.exit(2);
  if (!output.system[1].includes("adds no requirements")) process.exit(3);
  if (existsSync(join(root, ".closeout"))) process.exit(4);
  process.exit(0);
}

const event = { type: "session.idle", properties: { sessionID: "sess-1" } };
const calls = Number(process.env.CALLS || "1");
for (let i = 0; i < calls; i += 1) {
  await plugin.event({ event });
}
const nudgePath = join(root, ".closeout", "hook-nudges.json");
if (existsSync(join(root, ".closeout", "decisions"))) process.exit(7);

if (mode === "accepted") {
  if (prompts.length !== 0) process.exit(5);
  if (existsSync(nudgePath)) process.exit(6);
  process.exit(0);
}

if (mode === "rejected") {
  const expected = Math.min(calls, 3);
  if (prompts.length !== expected) process.exit(8);
  const counts = JSON.parse(readFileSync(nudgePath, "utf8"));
  const heads = Object.keys(counts);
  if (heads.length !== 1 || counts[heads[0]] !== expected) process.exit(9);
  const text = prompts[0].body.parts[0].text;
  if (!text.includes("quality/tests")) process.exit(10);
  if (text.includes("no changed path matches")) process.exit(13);
  if (text.includes("\"decision\": \"accepted\"")) process.exit(11);
  process.exit(0);
}

if (mode === "exhausted") {
  if (prompts.length !== 1) process.exit(14);
  if (!prompts[0].body.parts[0].text.includes("ask for help")) process.exit(15);
  process.exit(0);
}

process.exit(12);
