import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store, SupabaseBackend, type StoreData } from "../src/store.ts";

/** A PostgREST table with one row and the version guard, in memory. */
function fakeTable() {
  const state = { row: undefined as { id: string; version: number; data: StoreData } | undefined, calls: [] as string[] };
  const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    state.calls.push(method);
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
    if (method === "GET") return reply(state.row ? [state.row] : []);
    if (method === "POST") {
      if (state.row) return reply({ message: "duplicate key" }, 409);
      state.row = body as typeof state.row;
      return reply([state.row], 201);
    }
    const expected = Number(url.searchParams.get("version")?.replace("eq.", ""));
    if (!state.row || state.row.version !== expected) return reply([]);
    state.row = { ...state.row, ...body } as typeof state.row;
    return reply([state.row]);
  }) as typeof fetch;
  return { state, fetchFn };
}

const backend = (t: ReturnType<typeof fakeTable>) => new SupabaseBackend({ url: "https://x.supabase.co", key: "k", fetch: t.fetchFn });

test("first save inserts, later saves patch with the version guard", async () => {
  const t = fakeTable();
  const s = new Store(backend(t));
  await s.load();
  assert.equal(s.accounts().length, 0);
  s.update((d) => void (d.watches["w1"] = { id: "w1", account: "u", rule: { type: "balance_below", amount: 1 }, created: "2026-01-01", active: true, seen: [] }));
  await s.flush();
  assert.equal(t.state.row?.version, 1);
  s.update((d) => void (d.watches["w1"]!.note = "rent"));
  await s.flush();
  assert.equal(t.state.row?.version, 2);
  assert.equal(t.state.row?.data.watches["w1"]?.note, "rent");
  await s.flush();
  assert.deepEqual(t.state.calls.filter((c) => c !== "GET"), ["POST", "PATCH"], "a clean store does not write");

  const again = new Store(backend(t));
  await again.load();
  assert.equal(again.watches()[0]?.note, "rent");
});

test("a save that loses the race reloads and replays the changes", async () => {
  const t = fakeTable();
  const s = new Store(backend(t));
  await s.load();
  s.update((d) => void (d.accounts["a"] = { uid: "a", session_id: "s", currency: "DKK", identification_hash: "h" }));
  await s.flush();

  const other = new Store(backend(t));
  await other.load();
  other.update((d) => void (d.accounts["b"] = { uid: "b", session_id: "s", currency: "DKK", identification_hash: "h2" }));
  await other.flush();

  s.update((d) => void (d.accounts["a"]!.label = "Main"));
  await s.flush();
  assert.equal(t.state.row?.version, 3);
  assert.deepEqual(Object.keys(t.state.row!.data.accounts).sort(), ["a", "b"], "the other instance's account survives");
  assert.equal(t.state.row?.data.accounts["a"]?.label, "Main");
});

test("a file path still means the file backend", () => {
  const path = join(mkdtempSync(join(tmpdir(), "bank-")), "store.json");
  const s = new Store(path);
  s.update((d) => void (d.watches["w"] = { id: "w", account: "u", rule: { type: "balance_above", amount: 1 }, created: "2026-01-01", active: true, seen: [] }));
  assert.equal(new Store(path).watches().length, 1, "written synchronously");
});
