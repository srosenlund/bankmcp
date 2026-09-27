// First-run setup: takes the application id, the key file and a password,
// validates them and stores them in the data directory. Only reachable while
// the server has no working configuration.
import { createPrivateKey } from "node:crypto";
import { config, looksLikeUuid, saveKeyFile, saveSettings } from "./config.ts";
import { hashPassword } from "./auth.ts";
import { resetKeyCache } from "./enablebanking.ts";

export interface SetupInput {
  app_id?: string;
  pem?: string;
  password?: string;
  password2?: string;
  country?: string;
}

export function setupAvailable(): boolean {
  // Without a disk the page has nowhere to keep what it collects: configure through the environment.
  if (config.storeBackend !== "file") return false;
  const hasPassword = config.localMode || Boolean(config.adminPasswordHash || config.adminPassword);
  return !config.lockedByEnv && !(config.appId && (config.privateKey || config.privateKeyPath) && hasPassword);
}

/** Returns null on success, otherwise a message for the form. */
export function applySetup(input: SetupInput): string | null {
  const appId = (input.app_id ?? "").trim();
  const pem = (input.pem ?? "").trim();
  const password = input.password ?? "";
  const country = (input.country ?? "").trim().toUpperCase();

  if (!looksLikeUuid.test(appId)) return "The application id should be a UUID like 8d3f6c2a-1b4e-4f7a-9c2d-5e6f7a8b9c0d. It is shown on the application in the Enable Banking Control Panel.";
  if (!pem.includes("PRIVATE KEY")) return "That does not look like the key file. Choose the .pem file that downloaded when you registered the application.";
  try {
    createPrivateKey(pem);
  } catch {
    return "The key file could not be read as a private key.";
  }
  if (!config.localMode) {
    if (password.length < 12) return "Use a password of at least 12 characters. It is the only thing between the internet and your accounts.";
    if (password !== input.password2) return "The two passwords do not match.";
  }
  if (country && !/^[A-Z]{2}$/.test(country)) return "Country should be a two-letter code such as DK.";

  saveKeyFile(pem);
  saveSettings({ app_id: appId, admin_password_hash: config.localMode ? undefined : hashPassword(password), country: country || undefined, setup_completed: new Date().toISOString() });
  resetKeyCache();
  return null;
}
