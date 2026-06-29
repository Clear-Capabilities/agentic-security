import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();

// Static system prefix; cheaper model; no high-depth setting.
const SYSTEM = "You are a senior code reviewer. Be concise and concrete.";

const r = await client.messages.create({
  model: "claude-sonnet-4-6",
  effort: "low",
  system: SYSTEM,
  messages: [{ role: "user", content: q }],
});
