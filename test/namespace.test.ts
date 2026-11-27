import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
const { createServer } = await import("../src/mcp.ts");

async function toolNames(): Promise<string[]> {
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "t", version: "0" });
  await Promise.all([createServer().connect(a), client.connect(b)]);
  const { tools } = await client.listTools();
  await client.close();
  return tools.map((t) => t.name);
}

test("TOOL_NAMESPACE prefixes every tool name; unset leaves names unchanged", async () => {
  delete process.env.TOOL_NAMESPACE;
  const plain = await toolNames();
  assert.ok(plain.includes("list_accounts"));
  process.env.TOOL_NAMESPACE = "bank";
  try {
    assert.deepEqual(await toolNames(), plain.map((n) => `bank.${n}`));
  } finally {
    delete process.env.TOOL_NAMESPACE;
  }
});
