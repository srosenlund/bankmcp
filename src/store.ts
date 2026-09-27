// The only state this server keeps: bank sessions and account ids, watches,
// the OAuth clients/tokens for the MCP connector, and sign-ins waiting for the
// password. One JSON document, written atomically to a file or, on hosts
// without a disk, to a Supabase table guarded by a version column.
// Transactions and balances are never stored.
import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { config } from "./config.ts";

export interface StoredSession {
  id: string;
  bank: { name: string; country: string };
  psu_type: string;
  valid_until: string;
  created: string;
  /** Last status reported by Enable Banking, if we have checked. */
  status?: string;
  expiry_notified?: boolean;
}

export interface StoredAccount {
  uid: string;
  session_id: string;
  name?: string;
  product?: string;
  iban?: string;
  other_id?: string;
  currency: string;
  cash_account_type?: string;
  identification_hash: string;
  /** Your own name for the account, e.g. "Joint expenses". */
  label?: string;
  last_polled?: string;
}

export interface PendingAuth {
  state: string;
  bank: { name: string; country: string };
  started: string;
}

export type WatchRule =
  | { type: "balance_below"; amount: number }
  | { type: "balance_above"; amount: number }
  | { type: "large_debit"; amount: number }
  | { type: "credit_matching"; match: string; min_amount?: number }
  | { type: "debit_matching"; match: string; min_amount?: number }
  | { type: "credit_missing_by"; match: string; by_date: string; min_amount?: number };

export interface Watch {
  id: string;
  account: string;
  rule: WatchRule;
  note?: string;
  webhook_url?: string;
  created: string;
  active: boolean;
  last_checked?: string;
  last_triggered?: string;
  /** Transaction ids already reported, so a match notifies once. */
  seen: string[];
}

export interface OAuthClient {
  client_id: string;
  client_secret?: string;
  client_id_issued_at?: number;
  client_secret_expires_at?: number;
  redirect_uris: string[];
  client_name?: string;
  token_endpoint_auth_method?: string;
  grant_types?: string[];
  response_types?: string[];
  scope?: string;
  [key: string]: unknown;
}

export interface AuthCode {
  client_id: string;
  code_challenge: string;
  redirect_uri: string;
  resource?: string;
  scopes: string[];
  expires: number;
}

export interface Token {
  client_id: string;
  scopes: string[];
  expires: number;
  resource?: string;
  /** For refresh tokens: nothing extra. For access tokens: nothing extra. */
  kind: "access" | "refresh";
}

/** An authorization request waiting for the password, keyed by the id in the login form. */
export interface PendingLogin {
  client: OAuthClient;
  params: { redirectUri: string; codeChallenge: string; state?: string; scopes?: string[]; resource?: string };
  expires: number;
  attempts: number;
}

export interface StoreData {
  version: 1;
  sessions: Record<string, StoredSession>;
  accounts: Record<string, StoredAccount>;
  pending_auth: Record<string, PendingAuth>;
  watches: Record<string, Watch>;
  oauth: {
    clients: Record<string, OAuthClient>;
    codes: Record<string, AuthCode>;
    /** Keyed by sha256 of the token value. */
    tokens: Record<string, Token>;
    /** Fingerprint of the admin password the tokens were issued under. */
    password_fingerprint?: string;
    pending_logins: Record<string, PendingLogin>;
    /** Wrong-password counters per address; `until` is a lockout deadline. */
    login_failures: Record<string, { count: number; until: number }>;
  };
}

const empty = (): StoreData => ({
  version: 1,
  sessions: {},
  accounts: {},
  pending_auth: {},
  watches: {},
  oauth: { clients: {}, codes: {}, tokens: {}, pending_logins: {}, login_failures: {} },
});

const merge = (parsed: Partial<StoreData> | undefined): StoreData => ({
  ...empty(),
  ...(parsed ?? {}),
  oauth: { ...empty().oauth, ...(parsed?.oauth ?? {}) },
});

/** Where the document lives. A sync backend completes load/save before returning. */
export interface Backend {
  readonly sync: boolean;
  /** Where the document is, for status output. */
  readonly location: string;
  load(): StoreData | undefined | Promise<StoreData | undefined>;
  save(data: StoreData): void | Promise<void>;
}

/** Another process saved between our load and save. */
export class StoreConflict extends Error {
  constructor() {
    super("state changed since it was loaded");
  }
}

export class FileBackend implements Backend {
  readonly sync = true;
  readonly path: string;
  readonly location: string;

  constructor(path: string) {
    this.path = path;
    this.location = path;
  }

  load(): StoreData | undefined {
    // Earlier versions named the file openbank.json or openbanking.json.
    for (const old of ["openbanking.json", "openbank.json"]) {
      const legacy = join(dirname(this.path), old);
      if (!existsSync(this.path) && existsSync(legacy)) renameSync(legacy, this.path);
    }
    return existsSync(this.path) ? (JSON.parse(readFileSync(this.path, "utf8")) as StoreData) : undefined;
  }

  save(data: StoreData): void {
    try {
      mkdirSync(dirname(this.path), { recursive: true });
      const tmp = `${this.path}.tmp`;
      writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
      renameSync(tmp, this.path);
    } catch (err) {
      console.error(`[bank] cannot write state file ${this.path}: ${(err as Error).message}`);
      throw err;
    }
  }
}

export interface SupabaseOptions {
  url: string;
  /** The service role key; the table is never exposed to anon or authenticated. */
  key: string;
  schema?: string;
  table?: string;
  id?: string;
  fetch?: typeof fetch;
}

/** One row in a Supabase (PostgREST) table: id, version, data. The version
 *  column makes a save fail instead of overwriting a newer document.
 *
 *    create table public.bankmcp_state (
 *      id text primary key, version bigint not null default 1,
 *      data jsonb not null, updated_at timestamptz not null default now());
 *    alter table public.bankmcp_state enable row level security;
 *
 *  No policies: only the service role can reach the row. */
export class SupabaseBackend implements Backend {
  readonly sync = false;
  readonly location: string;
  private readonly opts: SupabaseOptions;
  private version = 0;

  constructor(opts: SupabaseOptions) {
    this.opts = opts;
    this.location = `${opts.url.replace(/\/+$/, "")} ${opts.schema ?? "public"}.${opts.table ?? "bankmcp_state"}`;
  }

  private async rest(method: "GET" | "POST" | "PATCH", query: string, body?: unknown): Promise<Array<{ version: number; data: StoreData }>> {
    const table = this.opts.table ?? "bankmcp_state";
    const res = await (this.opts.fetch ?? fetch)(`${this.opts.url.replace(/\/+$/, "")}/rest/v1/${table}${query}`, {
      method,
      headers: {
        apikey: this.opts.key,
        Authorization: `Bearer ${this.opts.key}`,
        Accept: "application/json",
        "Content-Type": "application/json",
        [method === "GET" ? "Accept-Profile" : "Content-Profile"]: this.opts.schema ?? "public",
        Prefer: "return=representation",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status === 409) throw new StoreConflict();
    if (!res.ok) throw new Error(`state store ${method} failed: HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
    return (await res.json()) as Array<{ version: number; data: StoreData }>;
  }

  async load(): Promise<StoreData | undefined> {
    const rows = await this.rest("GET", `?id=eq.${this.opts.id ?? "main"}&select=version,data`);
    this.version = rows[0]?.version ?? 0;
    return rows[0]?.data;
  }

  async save(data: StoreData): Promise<void> {
    const id = this.opts.id ?? "main";
    if (this.version === 0) {
      await this.rest("POST", "", { id, version: 1, data });
      this.version = 1;
      return;
    }
    const rows = await this.rest("PATCH", `?id=eq.${id}&version=eq.${this.version}`, { version: this.version + 1, data, updated_at: new Date().toISOString() });
    if (rows.length === 0) throw new StoreConflict();
    this.version += 1;
  }
}

export class Store {
  data: StoreData;
  /** Where the document is, for status output. */
  readonly location: string;
  private readonly backend: Backend;
  private dirty = false;
  /** Mutations since the last load, replayed if a save loses a race. They must not have side effects. */
  private pending: Array<(d: StoreData) => unknown> = [];

  constructor(backend: Backend | string = join(config.dataDir, "bank.json")) {
    this.backend = typeof backend === "string" ? new FileBackend(backend) : backend;
    this.location = this.backend.location;
    this.data = this.backend.sync ? merge(this.backend.load() as StoreData | undefined) : empty();
  }

  /** Async backends: read the current document before a request is handled. */
  async load(): Promise<void> {
    if (this.backend.sync) return;
    this.data = merge(await this.backend.load());
    this.dirty = false;
    this.pending = [];
  }

  /** Mutate under a callback. A file is written at once; an async backend is written by flush(). */
  update<T>(fn: (d: StoreData) => T): T {
    const result = fn(this.data);
    if (this.backend.sync) {
      this.backend.save(this.data);
    } else {
      this.dirty = true;
      this.pending.push(fn);
    }
    return result;
  }

  /** Persist what update() changed. If someone saved first, load their document and apply the changes again. */
  async flush(): Promise<void> {
    if (!this.dirty) return;
    for (let attempt = 1; ; attempt++) {
      try {
        await this.backend.save(this.data);
        this.dirty = false;
        this.pending = [];
        return;
      } catch (err) {
        if (!(err instanceof StoreConflict) || attempt >= 3) throw err;
        this.data = merge(await this.backend.load());
        for (const fn of this.pending) fn(this.data);
      }
    }
  }

  // --- Sessions & accounts ---

  addSession(session: { session_id: string; aspsp: { name: string; country: string }; psu_type: string; access: { valid_until: string }; accounts: Array<{ uid: string; name?: string; product?: string; currency: string; cash_account_type?: string; identification_hash: string; account_id?: { iban?: string; other?: { identification?: string } } }> }): void {
    this.update((d) => {
      d.sessions[session.session_id] = {
        id: session.session_id,
        bank: { name: session.aspsp.name, country: session.aspsp.country },
        psu_type: session.psu_type,
        valid_until: session.access.valid_until,
        created: new Date().toISOString(),
        status: "AUTHORIZED",
      };
      for (const a of session.accounts) {
        // A re-consent returns the same account under a new uid; carry the
        // label and watches over and drop the stale entry.
        const previous = Object.values(d.accounts).find((x) => x.identification_hash === a.identification_hash && x.uid !== a.uid);
        if (previous) {
          for (const w of Object.values(d.watches)) if (w.account === previous.uid) w.account = a.uid;
          delete d.accounts[previous.uid];
        }
        d.accounts[a.uid] = {
          uid: a.uid,
          session_id: session.session_id,
          name: a.name,
          product: a.product,
          iban: a.account_id?.iban,
          other_id: a.account_id?.other?.identification,
          currency: a.currency,
          cash_account_type: a.cash_account_type,
          identification_hash: a.identification_hash,
          label: previous?.label,
          last_polled: previous?.last_polled,
        };
      }
      // Sessions that no longer own any account are dead weight.
      for (const s of Object.values(d.sessions)) {
        if (s.id !== session.session_id && !Object.values(d.accounts).some((a) => a.session_id === s.id)) delete d.sessions[s.id];
      }
    });
  }

  removeSession(sessionId: string): void {
    this.update((d) => {
      delete d.sessions[sessionId];
      for (const a of Object.values(d.accounts)) if (a.session_id === sessionId) delete d.accounts[a.uid];
    });
  }

  accounts(): StoredAccount[] {
    return Object.values(this.data.accounts);
  }

  account(uid: string): StoredAccount | undefined {
    return this.data.accounts[uid];
  }

  sessions(): StoredSession[] {
    return Object.values(this.data.sessions);
  }

  // --- Pending bank authorizations ---

  addPendingAuth(p: PendingAuth): void {
    this.update((d) => {
      const cutoff = Date.now() - 60 * 60 * 1000;
      for (const [k, v] of Object.entries(d.pending_auth)) if (Date.parse(v.started) < cutoff) delete d.pending_auth[k];
      d.pending_auth[p.state] = p;
    });
  }

  takePendingAuth(state: string): PendingAuth | undefined {
    return this.update((d) => {
      const p = d.pending_auth[state];
      delete d.pending_auth[state];
      return p;
    });
  }

  // --- Watches ---

  watches(): Watch[] {
    return Object.values(this.data.watches);
  }

  putWatch(w: Watch): void {
    this.update((d) => {
      d.watches[w.id] = w;
    });
  }

  deleteWatch(id: string): boolean {
    return this.update((d) => {
      const had = id in d.watches;
      delete d.watches[id];
      return had;
    });
  }
}

function backendFromConfig(): Backend | string {
  if (config.storeBackend === "supabase") return new SupabaseBackend({ url: config.supabaseUrl, key: config.supabaseKey, schema: config.supabaseSchema });
  return join(config.dataDir, "bank.json");
}

let shared: Store | undefined;
export function store(): Store {
  return (shared ??= new Store(backendFromConfig()));
}
