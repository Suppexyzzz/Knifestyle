import type { Config, Context } from "@netlify/functions";
import { getConnectionString } from "@netlify/database";
import postgres from "postgres";
import { createHash, randomBytes, timingSafeEqual, pbkdf2 as pbkdf2Callback } from "node:crypto";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";
import path from "node:path";

const pbkdf2 = promisify(pbkdf2Callback);
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const DEVICE_RE = /^[0-9a-fA-F]{64}$/;
const USER_RE = /^[A-Za-z0-9_.-]{3,32}$/;
const VERSION_RE = /^[0-9A-Za-z][0-9A-Za-z._+-]{0,39}$/;
let sql: ReturnType<typeof postgres> | undefined;

function db() {
  if (!sql) {
    const connectionString = process.env.NETLIFY_DB_URL || getConnectionString();
    sql = postgres(connectionString, { max: 1, idle_timeout: 20, connect_timeout: 10 });
  }
  return sql;
}

export const config: Config = { path: "/api/*" };

export default async (request: Request, _context: Context): Promise<Response> => {
  try {
    const parts = new URL(request.url).pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
    const method = request.method.toUpperCase();
    if (parts[0] === "status" && method === "GET") return await statusResponse();
    if (parts[0] === "admin" && parts[1] === "setup" && method === "POST") return await setupOwner(await readJson(request));
    if (parts[0] === "auth" && parts[1] === "register" && method === "POST") return await register(request, await readJson(request));
    if (parts[0] === "auth" && parts[1] === "login" && method === "POST") return await login(request, await readJson(request));
    if (parts[0] === "loader" && parts[1] === "authorize" && method === "POST") return await authorizeDevice(request, await readJson(request));
    if (parts[0] === "loader" && parts[1] === "mod" && method === "GET") return await downloadMod(request);
    if (parts[0] === "admin" && parts[1] === "accounts" && parts.length === 2 && method === "GET") return await listAccounts(request);
    if (parts[0] === "admin" && parts[1] === "license-keys" && parts.length === 2 && method === "POST") return await createLicenseKey(request, await readJson(request));
    if (parts[0] === "admin" && parts[1] === "license-keys" && parts.length === 2 && method === "GET") return await listLicenseKeys(request);
    if (parts[0] === "admin" && parts[1] === "license-keys" && parts.length === 3 && method === "DELETE") return await deleteLicenseKey(request, parts[2]);
    if (parts[0] === "admin" && parts[1] === "accounts" && parts.length >= 3) {
      const username = parts[2];
      if (parts.length === 3 && method === "DELETE") return await deleteAccount(request, username);
      if (parts.length === 4 && parts[3] === "role" && method === "PATCH") return await setRole(request, username, await readJson(request));
      if (parts.length === 4 && parts[3] === "license" && method === "PATCH") return await setLicense(request, username, await readJson(request));
      if (parts.length === 4 && parts[3] === "reset-device" && method === "POST") return await resetDevice(request, username);
      if (parts.length === 4 && parts[3] === "password" && method === "POST") return await changePassword(request, username, await readJson(request));
    }
    if (parts[0] === "admin" && parts[1] === "release" && method === "POST") return await uploadRelease(request);
    return json({ error: "Nicht gefunden." }, 404);
  } catch (error) {
    console.error("KnifeStyle API request failed", error);
    return json({ error: "Interner Serverfehler." }, 500);
  }
};

async function statusResponse() {
  const setupKey = process.env.KNIFESTYLE_SETUP_KEY ?? "";
  const owner = await db()`SELECT 1 FROM accounts WHERE is_owner = TRUE LIMIT 1`;
  const release = await ensureInitialRelease();
  return json({ setupAvailable: setupKey.length > 0 && owner.length === 0, release: release ? {
    version: release.version, fileName: release.file_name, sha256: release.sha256, updatedUtc: release.updated_utc,
  } : null });
}

async function setupOwner(body: any) {
  const setupKey = process.env.KNIFESTYLE_SETUP_KEY ?? "";
  if (!setupKey || !fixedEquals(String(body.setupKey ?? ""), setupKey)) return json({ error: "Setup-Schlüssel ungültig." }, 403);
  const validation = validateCredentials(body.username, body.password);
  if (validation) return json({ error: validation }, 400);
  const credentials = await passwordParts(body.password);
  try {
    await db()`INSERT INTO accounts (username_key, username, password_salt, password_hash, is_admin, is_owner, enabled)
      VALUES (${normalizeUser(body.username)}, ${String(body.username).trim()}, ${credentials.salt}, ${credentials.hash}, TRUE, TRUE, TRUE)`;
    return json({ created: true });
  } catch (error: any) {
    if (error?.code === "23505") return json({ error: "Owner-Konto wurde bereits eingerichtet oder Username ist vergeben." }, 409);
    throw error;
  }
}

async function register(request: Request, body: any) {
  if (!(await allowAttempt(request, "register"))) return json({ error: "Zu viele Registrierungen. Bitte warte einige Minuten." }, 429);
  const validation = validateCredentials(body.username, body.password);
  if (validation) return json({ error: validation }, 400);
  if (typeof body.licenseKey !== "string" || !body.licenseKey.trim()) return json({ error: "Lizenzschlüssel erforderlich." }, 400);
  const username = String(body.username).trim();
  const userKey = normalizeUser(username);
  const keyHash = hash(body.licenseKey.trim().toUpperCase());
  const credentials = await passwordParts(body.password);
  try {
    const result = await db().begin(async tx => {
      const keys = await tx`SELECT id, duration_code FROM license_keys WHERE key_hash = ${keyHash} AND redeemed_utc IS NULL FOR UPDATE`;
      if (!keys.length) throw new RegistrationError();
      const expiry = expiryFor(keys[0].duration_code, new Date());
      if (expiry === INVALID_DURATION) throw new RegistrationError();
      const created = await tx`INSERT INTO accounts (username_key, username, password_salt, password_hash, enabled, expires_utc)
        VALUES (${userKey}, ${username}, ${credentials.salt}, ${credentials.hash}, TRUE, ${expiry})
        ON CONFLICT (username_key) DO NOTHING RETURNING username_key`;
      if (!created.length) return "username";
      await tx`UPDATE license_keys SET redeemed_utc = NOW(), redeemed_by = ${username} WHERE id = ${keys[0].id}`;
      return "created";
    });
    if (result === "username") return json({ error: "Dieser Username ist bereits vergeben." }, 409);
    return json({ created: true, message: "Konto erstellt. Du kannst dich jetzt im KnifeStyle Loader anmelden." }, 201);
  } catch (error) {
    if (error instanceof RegistrationError) return json({ error: "Lizenzschlüssel ungültig oder bereits verwendet." }, 400);
    throw error;
  }
}

async function login(request: Request, body: any) {
  if (!(await allowAttempt(request, "login"))) return json({ error: "Zu viele Login-Versuche. Warte einige Minuten." }, 429);
  const userKey = normalizeUser(body.username);
  const rows = await db()`SELECT * FROM accounts WHERE username_key = ${userKey} LIMIT 1`;
  const account = rows[0];
  if (!account || !isActive(account) || !(await verifyPassword(String(body.password ?? ""), account)))
    return json({ error: "Login ungültig oder Lizenz nicht aktiv." }, 401);
  const token = randomBytes(48).toString("base64url");
  const expires = new Date(Date.now() + SESSION_TTL_MS);
  await db()`INSERT INTO login_sessions (token_hash, username_key, expires_utc) VALUES (${hash(token)}, ${userKey}, ${expires})`;
  await clearAttempts(request, "login");
  return json({ accessToken: token, username: account.username, role: account.is_admin ? "admin" : "user", isOwner: account.is_owner, expiresUtc: expires });
}

async function authorizeDevice(request: Request, body: any) {
  const account = await authorizedAccount(request, false);
  if (!account) return json({ error: "Login erforderlich." }, 401);
  if (!isActive(account)) return json({ error: "Lizenz inaktiv oder abgelaufen." }, 403);
  if (typeof body.deviceId !== "string" || !DEVICE_RE.test(body.deviceId)) return json({ error: "Geräte-ID ungültig." }, 400);
  const result = await db().begin(async tx => {
    const rows = await tx`SELECT * FROM accounts WHERE username_key = ${account.username_key} FOR UPDATE`;
    const current = rows[0];
    if (!current || !isActive(current)) return "inactive";
    if (!current.device_id) await tx`UPDATE accounts SET device_id = ${body.deviceId}, last_device_id = ${body.deviceId}, last_seen_utc = NOW() WHERE username_key = ${current.username_key}`;
    else if (!fixedEquals(current.device_id, body.deviceId)) return "device";
    else await tx`UPDATE accounts SET last_device_id = ${body.deviceId}, last_seen_utc = NOW() WHERE username_key = ${current.username_key}`;
    return "ok";
  });
  if (result === "ok") return json({ authorized: true, account: account.username });
  if (result === "device") return json({ error: "Dieses Konto ist bereits an ein anderes Gerät gebunden. Bitte Admin um Geräte-Reset bitten." }, 403);
  return json({ error: "Lizenz inaktiv oder abgelaufen." }, 403);
}

async function downloadMod(request: Request) {
  const account = await authorizedAccount(request, false);
  if (!account) return json({ error: "Login erforderlich." }, 401);
  const deviceId = request.headers.get("X-Device-ID") ?? "";
  if (!DEVICE_RE.test(deviceId)) return json({ error: "Geräte-ID ungültig." }, 400);
  const rows = await db()`SELECT a.*, r.version, r.file_name, r.sha256, r.content FROM accounts a CROSS JOIN releases r
    WHERE a.username_key = ${account.username_key} AND r.id = 1 LIMIT 1`;
  const row = rows[0];
  if (!row || !isActive(row)) return json({ error: "Lizenz abgelaufen." }, 403);
  if (!row.device_id || !fixedEquals(row.device_id, deviceId)) return json({ error: "Gerät wurde noch nicht autorisiert." }, 403);
  return new Response(row.content, { status: 200, headers: {
    "Content-Type": "application/java-archive", "Content-Disposition": `attachment; filename="${safeFilename(row.file_name)}"`,
    "X-KnifeStyle-Version": row.version, "X-KnifeStyle-SHA256": row.sha256, "Cache-Control": "private, no-store",
  }});
}

async function listAccounts(request: Request) {
  if (!(await authorizedAccount(request, true))) return unauthorized();
  const rows = await db()`SELECT username, is_admin, is_owner, enabled, expires_utc, device_id, last_seen_utc, created_utc FROM accounts ORDER BY username`;
  return json(rows.map(r => ({ username: r.username, isAdmin: r.is_admin, isOwner: r.is_owner, enabled: r.enabled,
    expiresUtc: r.expires_utc, deviceBound: r.device_id !== null, lastSeenUtc: r.last_seen_utc, createdUtc: r.created_utc })));
}

async function createLicenseKey(request: Request, body: any) {
  if (!(await authorizedAccount(request, true))) return unauthorized();
  const labels: Record<string, string> = { month_1: "1 Monat", months_3: "3 Monate", year_1: "1 Jahr", lifetime: "Lifetime" };
  const durationCode = String(body.durationCode ?? "");
  if (!labels[durationCode]) return json({ error: "Ungültige Laufzeit." }, 400);
  const key = `KS-${randomBytes(16).toString("hex").toUpperCase()}`;
  const created = new Date();
  await db()`INSERT INTO license_keys (id, key_hash, duration_code, created_utc) VALUES (${randomBytes(16).toString("hex")}, ${hash(key)}, ${durationCode}, ${created})`;
  return json({ licenseKey: key, durationCode, durationLabel: labels[durationCode], createdUtc: created }, 201);
}

async function listLicenseKeys(request: Request) {
  if (!(await authorizedAccount(request, true))) return unauthorized();
  const rows = await db()`SELECT id, duration_code, created_utc, redeemed_utc, redeemed_by FROM license_keys ORDER BY created_utc DESC`;
  return json(rows.map(r => ({ id: r.id, durationCode: r.duration_code, createdUtc: r.created_utc, redeemedUtc: r.redeemed_utc, redeemedBy: r.redeemed_by })));
}

async function deleteLicenseKey(request: Request, id: string) {
  if (!(await authorizedAccount(request, true))) return unauthorized();
  const rows = await db()`DELETE FROM license_keys WHERE id = ${id} AND redeemed_utc IS NULL RETURNING id`;
  return rows.length ? json({ deleted: true }) : json({ error: "Unbenutzter Lizenzschlüssel nicht gefunden." }, 404);
}

async function setRole(request: Request, username: string, body: any) {
  const actor = await authorizedAccount(request, true);
  if (!actor) return unauthorized();
  if (!actor.is_owner) return json({ error: "Nur das Besitzerkonto kann Adminrollen vergeben oder entziehen." }, 403);
  if (typeof body.isAdmin !== "boolean") return json({ error: "Neue Rolle fehlt." }, 400);
  const rows = await db()`UPDATE accounts SET is_admin = ${body.isAdmin} WHERE username_key = ${normalizeUser(username)} AND is_owner = FALSE RETURNING username_key`;
  if (rows.length) return json({ updated: true, isAdmin: body.isAdmin });
  const owner = await db()`SELECT 1 FROM accounts WHERE username_key = ${normalizeUser(username)} AND is_owner = TRUE`;
  return owner.length ? json({ error: "Das Besitzerkonto kann nicht herabgestuft werden." }, 403) : json({ error: "Konto nicht gefunden." }, 404);
}

async function setLicense(request: Request, username: string, body: any) {
  if (!(await authorizedAccount(request, true))) return unauthorized();
  const enabled = typeof body.enabled === "boolean" ? body.enabled : null;
  const expires = body.expiresUtc ? new Date(body.expiresUtc) : null;
  if (expires && !Number.isFinite(expires.getTime())) return json({ error: "Ablaufdatum ungültig." }, 400);
  const rows = await db()`UPDATE accounts SET enabled = COALESCE(${enabled}, enabled), expires_utc = COALESCE(${expires}, expires_utc)
    WHERE username_key = ${normalizeUser(username)} AND is_owner = FALSE RETURNING username_key`;
  return rows.length ? json({ updated: true }) : json({ error: "Konto nicht gefunden." }, 404);
}

async function resetDevice(request: Request, username: string) {
  if (!(await authorizedAccount(request, true))) return unauthorized();
  const rows = await db()`UPDATE accounts SET device_id = NULL, last_device_id = NULL WHERE username_key = ${normalizeUser(username)} AND is_owner = FALSE RETURNING username_key`;
  return rows.length ? json({ reset: true }) : json({ error: "Konto nicht gefunden." }, 404);
}

async function changePassword(request: Request, username: string, body: any) {
  if (!(await authorizedAccount(request, true))) return unauthorized();
  if (typeof body.password !== "string" || body.password.length < 10 || body.password.length > 128) return json({ error: "Passwort muss mindestens 10 Zeichen haben." }, 400);
  const credentials = await passwordParts(body.password);
  const rows = await db()`UPDATE accounts SET password_salt = ${credentials.salt}, password_hash = ${credentials.hash}
    WHERE username_key = ${normalizeUser(username)} AND is_owner = FALSE RETURNING username_key`;
  return rows.length ? json({ updated: true }) : json({ error: "Konto nicht gefunden." }, 404);
}

async function deleteAccount(request: Request, username: string) {
  if (!(await authorizedAccount(request, true))) return unauthorized();
  const rows = await db()`DELETE FROM accounts WHERE username_key = ${normalizeUser(username)} AND is_owner = FALSE RETURNING username_key`;
  return rows.length ? json({ deleted: true }) : json({ error: "Konto nicht gefunden." }, 404);
}

async function uploadRelease(request: Request) {
  if (!(await authorizedAccount(request, true))) return unauthorized();
  const form = await request.formData();
  const file = form.get("file");
  const version = String(form.get("version") ?? "").trim();
  if (!(file instanceof File) || !file.name.toLowerCase().endsWith(".jar") || file.size < 1024 || file.size > 4_500_000)
    return json({ error: "Eine gültige JAR-Datei bis 4,5 MB auswählen (Netlify Function Upload-Limit)." }, 400);
  if (!VERSION_RE.test(version)) return json({ error: "Versionsname ungültig." }, 400);
  const content = Buffer.from(await file.arrayBuffer());
  const sha256 = createHash("sha256").update(content).digest("hex").toUpperCase();
  const fileName = `knifestyle-${version}.jar`;
  const updatedUtc = new Date();
  await db()`INSERT INTO releases (id, version, file_name, sha256, updated_utc, content)
    VALUES (1, ${version}, ${fileName}, ${sha256}, ${updatedUtc}, ${content}) ON CONFLICT (id) DO UPDATE SET
      version = EXCLUDED.version, file_name = EXCLUDED.file_name, sha256 = EXCLUDED.sha256,
      updated_utc = EXCLUDED.updated_utc, content = EXCLUDED.content`;
  return json({ version, fileName, sha256, updatedUtc });
}

async function ensureInitialRelease() {
  const current = await db()`SELECT version, file_name, sha256, updated_utc FROM releases WHERE id = 1 LIMIT 1`;
  if (current.length) return current[0];
  const fileName = "knifestyle-1.0.0.jar";
  const bytes = await readFile(path.join(process.cwd(), "releases", fileName));
  const sha256 = createHash("sha256").update(bytes).digest("hex").toUpperCase();
  const updatedUtc = new Date();
  await db()`INSERT INTO releases (id, version, file_name, sha256, updated_utc, content)
    VALUES (1, '1.0.0', ${fileName}, ${sha256}, ${updatedUtc}, ${bytes}) ON CONFLICT (id) DO NOTHING`;
  return (await db()`SELECT version, file_name, sha256, updated_utc FROM releases WHERE id = 1 LIMIT 1`)[0] ?? null;
}

async function authorizedAccount(request: Request, adminOnly: boolean) {
  const header = request.headers.get("authorization") ?? "";
  if (!header.toLowerCase().startsWith("bearer ")) return null;
  const rows = await db()`SELECT a.* FROM login_sessions s JOIN accounts a ON a.username_key = s.username_key
    WHERE s.token_hash = ${hash(header.slice(7).trim())} AND s.expires_utc > NOW() LIMIT 1`;
  const account = rows[0];
  if (!account || !isActive(account) || (adminOnly && !account.is_admin)) return null;
  return account;
}

async function allowAttempt(request: Request, kind: string) {
  const ip = request.headers.get("x-nf-client-connection-ip") ?? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const bucket = `${kind}:${hash(ip)}`;
  const rows = await db()`INSERT INTO auth_attempts (bucket, started_utc, attempt_count) VALUES (${bucket}, NOW(), 1)
    ON CONFLICT (bucket) DO UPDATE SET
      started_utc = CASE WHEN auth_attempts.started_utc < NOW() - INTERVAL '5 minutes' THEN NOW() ELSE auth_attempts.started_utc END,
      attempt_count = CASE WHEN auth_attempts.started_utc < NOW() - INTERVAL '5 minutes' THEN 1 ELSE auth_attempts.attempt_count + 1 END
    RETURNING attempt_count`;
  return Number(rows[0]?.attempt_count ?? 99) <= 8;
}

async function clearAttempts(request: Request, kind: string) {
  const ip = request.headers.get("x-nf-client-connection-ip") ?? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  await db()`DELETE FROM auth_attempts WHERE bucket = ${`${kind}:${hash(ip)}`}`;
}

async function passwordParts(password: string) {
  const salt = randomBytes(16);
  const derived = await pbkdf2(password, salt, 310_000, 32, "sha256");
  return { salt: salt.toString("base64"), hash: Buffer.from(derived).toString("base64") };
}

async function verifyPassword(password: string, account: any) {
  try {
    const expected = Buffer.from(account.password_hash, "base64");
    const actual = Buffer.from(await pbkdf2(password, Buffer.from(account.password_salt, "base64"), 310_000, expected.length, "sha256"));
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch { return false; }
}

function validateCredentials(username: unknown, password: unknown) {
  if (typeof username !== "string" || !USER_RE.test(username)) return "Username: 3–32 Zeichen, Buchstaben/Zahlen/._-";
  if (typeof password !== "string" || password.length < 10 || password.length > 128) return "Passwort muss 10–128 Zeichen haben.";
  return null;
}
function isActive(account: any) { return !!account.enabled && (!account.expires_utc || new Date(account.expires_utc).getTime() > Date.now()); }
function normalizeUser(value: unknown) { return String(value ?? "").trim().toLowerCase(); }
function hash(value: string) { return createHash("sha256").update(value, "utf8").digest("hex").toUpperCase(); }
function fixedEquals(a: string, b: string) { const left = Buffer.from(a, "utf8"), right = Buffer.from(b, "utf8"); return left.length === right.length && timingSafeEqual(left, right); }
function safeFilename(value: string) { return path.basename(value).replace(/["\r\n]/g, ""); }
function json(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } }); }
function unauthorized() { return json({ error: "Login erforderlich." }, 401); }
async function readJson(request: Request) { try { return await request.json() as any; } catch { return {}; } }
const INVALID_DURATION = Symbol("invalid-duration");
function expiryFor(code: string, from: Date): Date | null | typeof INVALID_DURATION {
  const result = new Date(from);
  switch (code) {
    case "month_1": result.setUTCMonth(result.getUTCMonth() + 1); return result;
    case "months_3": result.setUTCMonth(result.getUTCMonth() + 3); return result;
    case "year_1": result.setUTCFullYear(result.getUTCFullYear() + 1); return result;
    case "lifetime": return null;
    default: return INVALID_DURATION;
  }
}
class RegistrationError extends Error {}

