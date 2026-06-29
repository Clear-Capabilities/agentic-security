import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();

// Cache-killer: a per-request id in the system prefix invalidates the cache.
const system = `You are a senior code reviewer. Session: ${Date.now()}. Be thorough.`;

const r = await client.messages.create({
  model: "claude-opus-4-8",
  effort: "high",
  system,
  messages: [{ role: "user", content: q }],
});
