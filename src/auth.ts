// A complete OAuth 2.1 authorization server with exactly one user: you.
// The MCP SDK provides discovery, dynamic client registration, PKCE checks
// and the token endpoint; this file supplies the storage behind them and a
// password login page. Tokens are stored hashed. Everything, including the
// sign-ins waiting for a password, lives in the store, so any instance of the
// server can finish a flow another instance started.
import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import type { Response } from "express";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { InvalidGrantError, InvalidTokenError, InvalidClientMetadataError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { config } from "./config.ts";
import { loginPage } from "./pages.ts";
export { loginPage, shell as page } from "./pages.ts";
import type { Store, StoreData, OAuthClient, Token } from "./store.ts";

const ACCESS_TTL = 60 * 60; // 1 hour
const REFRESH_TTL = 90 * 24 * 60 * 60; // 90 days
const CODE_TTL = 10 * 60;
const LOGIN_TTL = 30 * 60;

// --- Password ---

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64);
  return `scrypt$${salt.toString("base64")}$${hash.toString("base64")}`;
}

export function verifyPassword(password: string): boolean {
  if (config.adminPasswordHash) {
    const [scheme, salt, expected] = config.adminPasswordHash.split("$");
    if (scheme !== "scrypt" || !salt || !expected) return false;
    const actual = scryptSync(password, Buffer.from(salt, "base64"), 64);
    const exp = Buffer.from(expected, "base64");
    return actual.length === exp.length && timingSafeEqual(actual, exp);
  }
  if (config.adminPassword) {
    const a = Buffer.from(password);
    const b = Buffer.from(config.adminPassword);
    return a.length === b.length && timingSafeEqual(a, b);
  }
  return false;
}

export function redirectAllowed(uri: string): boolean {
  try {
    const host = new URL(uri).hostname.toLowerCase();
    return config.allowedRedirectHosts.some((h) => host === h || host.endsWith(`.${h}`));
  } catch {
    return false;
  }
}

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const token = () => randomBytes(32).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);

/** Drop expired sign-ins and lockouts. Called inside a store update. */
function sweep(d: StoreData): void {
  const t = now();
  for (const [k, v] of Object.entries(d.oauth.pending_logins)) if (v.expires < t) delete d.oauth.pending_logins[k];
  for (const [k, v] of Object.entries(d.oauth.login_failures)) if (v.until && v.until < t) delete d.oauth.login_failures[k];
}

export interface LoginEvent {
  ok: boolean;
  ip: string;
  clientName?: string;
  reason?: string;
}

type LoginOutcome =
  | { kind: "locked" }
  | { kind: "expired" }
  | { kind: "wrong"; clientName?: string; requestId?: string }
  | { kind: "ok"; clientName?: string; redirect: string };

export class SingleUserProvider implements OAuthServerProvider {
  private store: Store;
  private onLogin?: (e: LoginEvent) => void;

  constructor(store: Store, opts: { onLogin?: (e: LoginEvent) => void } = {}) {
    this.store = store;
    this.onLogin = opts.onLogin;
  }

  /** Every token, pending code and pending sign-in is dropped. Used when the admin password changes. */
  async revokeAll(): Promise<void> {
    this.store.update((d) => {
      d.oauth.tokens = {};
      d.oauth.codes = {};
      d.oauth.pending_logins = {};
    });
    await this.store.flush();
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    const store = this.store;
    return {
      getClient(clientId) {
        return store.data.oauth.clients[clientId] as OAuthClientInformationFull | undefined;
      },
      async registerClient(client) {
        for (const uri of client.redirect_uris) {
          if (!redirectAllowed(uri)) throw new InvalidClientMetadataError(`redirect_uri host not allowed: ${new URL(uri).hostname}. Set ALLOWED_REDIRECT_HOSTS on the server to permit it.`);
        }
        // The SDK handler has already generated the id and, for confidential clients, the secret.
        const incoming = client as Partial<OAuthClient>;
        const full: OAuthClient = {
          ...(client as OAuthClient),
          client_id: incoming.client_id ?? randomBytes(16).toString("hex"),
          client_id_issued_at: incoming.client_id_issued_at ?? now(),
        };
        store.update((d) => {
          // Keep the store small: a connector re-registers when it is re-added.
          // Only clients without a live token are dropped, so a re-registering
          // connector cannot evict a client that still refreshes (the Finance job).
          const live = new Set(Object.values(d.oauth.tokens).filter((t) => t.expires > now()).map((t) => t.client_id));
          const idle = Object.keys(d.oauth.clients).filter((id) => !live.has(id));
          // At most 20 idle clients remain, counting the one being added.
          if (idle.length >= 20) for (const id of idle.slice(0, idle.length - 19)) delete d.oauth.clients[id];
          d.oauth.clients[full.client_id] = full;
        });
        await store.flush();
        return full as OAuthClientInformationFull;
      },
    };
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const id = token();
    this.store.update((d) => {
      sweep(d);
      d.oauth.pending_logins[id] = {
        client: client as OAuthClient,
        params: { redirectUri: params.redirectUri, codeChallenge: params.codeChallenge, state: params.state, scopes: params.scopes, resource: params.resource?.href },
        expires: now() + LOGIN_TTL,
        attempts: 0,
      };
    });
    await this.store.flush();
    res.status(200).type("html").send(loginPage({ requestId: id, clientName: client.client_name, returnTo: new URL(params.redirectUri).hostname }));
  }

  /** Called by POST /login. Returns the redirect URL on success, or an error message. */
  async completeLogin(requestId: string, password: string, ip: string): Promise<{ redirect: string } | { error: string; requestId?: string }> {
    // The code is minted outside the update so a replayed update stores the same one.
    const code = token();
    const outcome = this.store.update((d): LoginOutcome => {
      sweep(d);
      const lock = d.oauth.login_failures[ip];
      if (lock && lock.until > now()) return { kind: "locked" };
      const pending = d.oauth.pending_logins[requestId];
      if (!pending) return { kind: "expired" };
      if (!verifyPassword(password)) {
        pending.attempts += 1;
        const f = d.oauth.login_failures[ip] ?? { count: 0, until: 0 };
        f.count += 1;
        if (f.count >= 5) f.until = now() + 15 * 60;
        d.oauth.login_failures[ip] = f;
        if (pending.attempts >= 5) delete d.oauth.pending_logins[requestId];
        return { kind: "wrong", clientName: pending.client.client_name, requestId: pending.attempts < 5 ? requestId : undefined };
      }
      delete d.oauth.pending_logins[requestId];
      delete d.oauth.login_failures[ip];
      for (const [c, v] of Object.entries(d.oauth.codes)) if (v.expires < now()) delete d.oauth.codes[c];
      d.oauth.codes[sha256(code)] = {
        client_id: pending.client.client_id,
        code_challenge: pending.params.codeChallenge,
        redirect_uri: pending.params.redirectUri,
        resource: pending.params.resource,
        scopes: pending.params.scopes ?? [],
        expires: now() + CODE_TTL,
      };
      const url = new URL(pending.params.redirectUri);
      url.searchParams.set("code", code);
      if (pending.params.state) url.searchParams.set("state", pending.params.state);
      return { kind: "ok", clientName: pending.client.client_name, redirect: url.href };
    });
    await this.store.flush();

    switch (outcome.kind) {
      case "locked":
        this.onLogin?.({ ok: false, ip, reason: "locked out" });
        return { error: "Too many attempts. Try again in a few minutes." };
      case "expired":
        return { error: "This sign-in page has expired or the server restarted. Go back to your assistant, click Connect again, and enter the password within 30 minutes." };
      case "wrong":
        this.onLogin?.({ ok: false, ip, clientName: outcome.clientName, reason: "wrong password" });
        return { error: "Wrong password.", requestId: outcome.requestId };
      case "ok":
        this.onLogin?.({ ok: true, ip, clientName: outcome.clientName });
        return { redirect: outcome.redirect };
    }
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    const c = this.store.data.oauth.codes[sha256(authorizationCode)];
    if (!c || c.client_id !== client.client_id || c.expires < now()) throw new InvalidGrantError("Invalid or expired authorization code");
    return c.code_challenge;
  }

  async exchangeAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string, _codeVerifier?: string, redirectUri?: string, resource?: URL): Promise<OAuthTokens> {
    const key = sha256(authorizationCode);
    const c = this.store.data.oauth.codes[key];
    if (!c || c.client_id !== client.client_id || c.expires < now()) throw new InvalidGrantError("Invalid or expired authorization code");
    if (redirectUri && redirectUri !== c.redirect_uri) throw new InvalidGrantError("redirect_uri does not match");
    if (resource && c.resource && resource.href !== c.resource) throw new InvalidGrantError("resource does not match");
    const minted = { access: token(), refresh: token() };
    const out = this.store.update((d) => {
      delete d.oauth.codes[key];
      return this.issue(d.oauth.tokens, client.client_id, c.scopes, c.resource, minted);
    });
    await this.store.flush();
    return out;
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[], resource?: URL): Promise<OAuthTokens> {
    const key = sha256(refreshToken);
    const t = this.store.data.oauth.tokens[key];
    if (!t || t.kind !== "refresh" || t.client_id !== client.client_id) throw new InvalidGrantError("Invalid refresh token");
    if (t.expires < now()) throw new InvalidGrantError("Refresh token expired");
    if (resource && t.resource && resource.href !== t.resource) throw new InvalidGrantError("resource does not match");
    const minted = { access: token(), refresh: token() };
    const out = this.store.update((d) => {
      delete d.oauth.tokens[key];
      return this.issue(d.oauth.tokens, client.client_id, scopes?.length ? scopes : t.scopes, t.resource, minted);
    });
    await this.store.flush();
    return out;
  }

  async verifyAccessToken(tokenValue: string): Promise<AuthInfo> {
    const t = this.store.data.oauth.tokens[sha256(tokenValue)];
    if (!t || t.kind !== "access") throw new InvalidTokenError("Invalid access token");
    if (t.expires < now()) throw new InvalidTokenError("Access token expired");
    return { token: tokenValue, clientId: t.client_id, scopes: t.scopes, expiresAt: t.expires, resource: t.resource ? new URL(t.resource) : undefined };
  }

  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const key = sha256(request.token);
    const t = this.store.data.oauth.tokens[key];
    if (t && t.client_id === client.client_id) {
      this.store.update((d) => void delete d.oauth.tokens[key]);
      await this.store.flush();
    }
  }

  private issue(tokens: Record<string, Token>, clientId: string, scopes: string[], resource: string | undefined, minted: { access: string; refresh: string }): OAuthTokens {
    for (const [k, v] of Object.entries(tokens)) if (v.expires < now()) delete tokens[k];
    tokens[sha256(minted.access)] = { kind: "access", client_id: clientId, scopes, resource, expires: now() + ACCESS_TTL };
    tokens[sha256(minted.refresh)] = { kind: "refresh", client_id: clientId, scopes, resource, expires: now() + REFRESH_TTL };
    return { access_token: minted.access, token_type: "bearer", expires_in: ACCESS_TTL, refresh_token: minted.refresh, scope: scopes.join(" ") || undefined };
  }
}
