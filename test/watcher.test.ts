import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../src/watcher.ts";
import type { StoredAccount, Watch } from "../src/store.ts";

const account: StoredAccount = { uid: "u1", session_id: "s1", label: "Everyday", currency: "DKK", identification_hash: "h" };
const watch = (rule: Watch["rule"], extra: Partial<Watch> = {}): Watch => ({ id: "w", account: "u1", rule, created: "2026-09-01T00:00:00Z", active: true, seen: [], ...extra });
const tx = (id: string, amount: number, counterparty: string, date = "2026-09-05") => ({ id, date, amount, currency: "DKK", counterparty, status: "BOOK" });

test("balance_below fires once per 24h", () => {
  const w = watch({ type: "balance_below", amount: 1000 });
  assert.equal(evaluate(account, [w], 500, []).length, 1);
  assert.equal(evaluate(account, [w], 400, []).length, 0);
  assert.equal(evaluate(account, [w], 5000, []).length, 0);
});

test("large_debit fires once per transaction", () => {
  const w = watch({ type: "large_debit", amount: 5000 });
  const txs = [tx("a", -6000, "Dentist"), tx("b", -100, "Netto")];
  assert.equal(evaluate(account, [w], undefined, txs).length, 1);
  assert.equal(evaluate(account, [w], undefined, txs).length, 0);
  assert.equal(evaluate(account, [w], undefined, [...txs, tx("c", -9000, "Garage")]).length, 1);
});

test("credit_missing_by notifies on arrival and deactivates", () => {
  const w = watch({ type: "credit_missing_by", match: "acme", by_date: "2026-09-30" });
  assert.equal(evaluate(account, [w], undefined, [tx("old", 50000, "Acme Ltd", "2026-08-20")], "2026-09-06").length, 0, "credits before the watch was created do not count");
  assert.equal(w.active, true);
  const events = evaluate(account, [w], undefined, [tx("new", 50000, "ACME LTD")], "2026-09-06");
  assert.equal(events.length, 1);
  assert.match(events[0]!.text, /arrived/);
  assert.equal(w.active, false);
});

test("credit_missing_by fires on the deadline", () => {
  const w = watch({ type: "credit_missing_by", match: "acme", by_date: "2026-09-30" });
  assert.equal(evaluate(account, [w], undefined, [], "2026-09-29").length, 0);
  const events = evaluate(account, [w], undefined, [], "2026-09-30");
  assert.equal(events.length, 1);
  assert.match(events[0]!.text, /no payment/);
  assert.equal(w.active, false);
});

test("credit_matching matches description too and respects min_amount", () => {
  const w = watch({ type: "credit_matching", match: "payout", min_amount: 1000 });
  const txs = [{ ...tx("a", 2500, "STRIPE PAYMENTS"), description: "Stripe payout" }, { ...tx("b", 50, "STRIPE PAYMENTS"), description: "Stripe refund" }];
  assert.equal(evaluate(account, [w], undefined, txs).length, 1);
});

test("create_watch cannot choose a webhook destination; only the operator's NOTIFY_WEBHOOK_URL is used", async () => {
  const { createServer } = await import("../src/mcp.ts");
  const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
  const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");
  const [serverSide, clientSide] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([createServer().connect(serverSide), client.connect(clientSide)]);
  const tool = (await client.listTools()).tools.find((t) => t.name === "create_watch");
  assert.ok(tool, "create_watch is registered");
  assert.equal("webhook_url" in (tool.inputSchema.properties ?? {}), false);
  await client.close();
});
