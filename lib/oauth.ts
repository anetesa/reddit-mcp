import { getPublicOrigin } from "mcp-handler";
import { open, pkceChallenge, seal } from "./crypto";
import { allowedUser, authorizeUrl, exchangeCode, RedditError } from "./reddit";

// A small OAuth 2.1 authorization server whose sign-in is Reddit's: the MCP client sends the owner to Reddit's
// consent page for this app, and only the Reddit account in REDDIT_ALLOWED_USER gets through. The owner's Reddit
// refresh token then lives sealed inside the client's access and refresh tokens; nothing is stored server-side.
//
// Clients identify themselves either with a Client ID Metadata Document (an https URL, MCP 2026-07-28) or by
// dynamic registration (RFC 7591), whose client_id is the sealed registration itself.

export const SCOPE = "reddit";
const CODE_TTL_MS = 5 * 60_000;
const REQUEST_TTL_MS = 10 * 60_000;
const ACCESS_TTL_S = 3600;

export const origin = (req: Request) => getPublicOrigin(req);

export function authorizationServerMetadata(issuer: string) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [SCOPE],
    client_id_metadata_document_supported: true,
  };
}

export class OAuthError extends Error {
  constructor(
    readonly code: string,
    description: string,
    readonly status = 400,
  ) {
    super(description);
  }

  response(): Response {
    return Response.json({ error: this.code, error_description: this.message }, { status: this.status, headers: CORS });
  }
}

export const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, MCP-Protocol-Version",
};

export interface Client {
  clientId: string;
  name: string;
  redirectUris: string[];
}

const UNSAFE_SCHEMES = new Set(["javascript:", "data:", "file:", "vbscript:", "blob:"]);

/** https; http only to this machine (desktop clients); an app's own scheme ("claude://…"); never a fragment. */
function validRedirect(uri: unknown): uri is string {
  if (typeof uri !== "string") return false;
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.hash || UNSAFE_SCHEMES.has(url.protocol)) return false;
  if (url.protocol === "https:") return true;
  if (url.protocol === "http:") return url.hostname === "localhost" || url.hostname === "127.0.0.1";
  return true;
}

export async function register(body: Record<string, unknown>) {
  const redirectUris = body.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0 || !redirectUris.every(validRedirect)) {
    throw new OAuthError("invalid_redirect_uri", "redirect_uris must be https URLs (or loopback / app schemes).");
  }
  const name = typeof body.client_name === "string" ? body.client_name.slice(0, 100) : "MCP client";
  const clientId = await seal("client", { r: redirectUris, n: name });
  return {
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_name: name,
    redirect_uris: redirectUris,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  };
}

const metadataCache = new Map<string, { client: Client; until: number }>();

export async function resolveClient(clientId: string | null): Promise<Client> {
  if (!clientId) throw new OAuthError("invalid_client", "client_id is missing.");
  if (clientId.startsWith("https://")) return metadataDocumentClient(clientId);
  const registered = await open<{ r: string[]; n: string }>("client", clientId);
  if (!registered) throw new OAuthError("invalid_client", "Unknown client_id: register again.");
  return { clientId, name: registered.n, redirectUris: registered.r };
}

async function metadataDocumentClient(url: string): Promise<Client> {
  const cached = metadataCache.get(url);
  if (cached && cached.until > Date.now()) return cached.client;
  let doc: Record<string, unknown>;
  try {
    const response = await fetch(url, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(5000), redirect: "error" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const textBody = await response.text();
    if (textBody.length > 10_000) throw new Error("document too large");
    doc = JSON.parse(textBody);
  } catch (e) {
    throw new OAuthError("invalid_client", `Could not read the client metadata document: ${(e as Error).message}`);
  }
  if (doc.client_id !== url) throw new OAuthError("invalid_client", "The metadata document's client_id does not match its URL.");
  const redirectUris = doc.redirect_uris;
  if (!Array.isArray(redirectUris) || !redirectUris.every(validRedirect)) {
    throw new OAuthError("invalid_client", "The metadata document has no valid redirect_uris.");
  }
  const client = { clientId: url, name: typeof doc.client_name === "string" ? doc.client_name : new URL(url).host, redirectUris };
  metadataCache.set(url, { client, until: Date.now() + 10 * 60_000 });
  return client;
}

export interface AuthorizeRequest {
  client: Client;
  redirectUri: string;
  state: string | null;
  codeChallenge: string;
  scope: string;
  resource: string | null;
}

/** Checks an /authorize request. Errors that can be reported to the client come back as a redirect URL. */
export async function parseAuthorize(params: URLSearchParams): Promise<AuthorizeRequest> {
  const client = await resolveClient(params.get("client_id"));
  const redirectUri = params.get("redirect_uri") ?? (client.redirectUris.length === 1 ? client.redirectUris[0]! : "");
  if (!client.redirectUris.includes(redirectUri)) {
    throw new OAuthError("invalid_request", "redirect_uri is not registered for this client.");
  }
  if (params.get("response_type") !== "code") throw new OAuthError("unsupported_response_type", "Only response_type=code.");
  const codeChallenge = params.get("code_challenge");
  if (!codeChallenge || params.get("code_challenge_method") !== "S256") {
    throw new OAuthError("invalid_request", "PKCE with code_challenge_method=S256 is required.");
  }
  return { client, redirectUri, state: params.get("state"), codeChallenge, scope: SCOPE, resource: params.get("resource") };
}

export function redirectWith(redirectUri: string, values: Record<string, string | null>): string {
  const url = new URL(redirectUri);
  for (const [name, value] of Object.entries(values)) if (value != null) url.searchParams.set(name, value);
  return url.toString();
}

interface PendingRequest {
  cid: string;
  ru: string;
  cc: string;
  st: string | null;
  exp: number;
}

interface SealedCode {
  rt: string;
  u: string;
  cid: string;
  ru: string;
  cc: string;
  exp: number;
}

export interface AccessGrant {
  rt: string;
  u: string;
  exp: number;
}

export const redditCallback = (issuer: string) => `${issuer}/oauth/callback`;

/** Where /oauth/authorize sends the browser: Reddit's consent page, carrying the client's request sealed as its state. */
export async function startSignIn(request: AuthorizeRequest, issuer: string): Promise<string> {
  const state = await seal("request", {
    cid: request.client.clientId,
    ru: request.redirectUri,
    cc: request.codeChallenge,
    st: request.state,
    exp: Date.now() + REQUEST_TTL_MS,
  } satisfies PendingRequest);
  return authorizeUrl(redditCallback(issuer), state);
}

/**
 * Reddit's redirect back: checks the account and returns where to send the browser (the client's redirect URI with
 * a code or an error). Throws OAuthError when the request itself cannot be trusted, so nothing is redirected.
 */
export async function finishSignIn(params: URLSearchParams, issuer: string): Promise<string> {
  const pending = await open<PendingRequest>("request", params.get("state"));
  if (!pending || pending.exp < Date.now()) throw new OAuthError("invalid_request", "The sign-in took too long or was tampered with. Connect again.");
  const back = (values: Record<string, string | null>) => redirectWith(pending.ru, { ...values, state: pending.st });
  const denied = params.get("error");
  if (denied) return back({ error: "access_denied", error_description: `Reddit: ${denied}` });
  let account;
  try {
    account = await exchangeCode(params.get("code") ?? "", redditCallback(issuer));
  } catch (e) {
    if (e instanceof RedditError) return back({ error: "access_denied", error_description: e.message });
    throw e;
  }
  if (!allowedUser(account.user)) {
    return back({ error: "access_denied", error_description: `u/${account.user} may not use this server.` });
  }
  const code = await seal("code", {
    rt: account.refreshToken,
    u: account.user,
    cid: pending.cid,
    ru: pending.ru,
    cc: pending.cc,
    exp: Date.now() + CODE_TTL_MS,
  } satisfies SealedCode);
  return back({ code });
}

export async function token(form: URLSearchParams) {
  const grant = form.get("grant_type");
  if (grant === "authorization_code") {
    const code = await open<SealedCode>("code", form.get("code"));
    if (!code || code.exp < Date.now()) throw new OAuthError("invalid_grant", "The code is invalid or expired.");
    if (form.get("client_id") && form.get("client_id") !== code.cid) throw new OAuthError("invalid_grant", "Code issued to another client.");
    if (form.get("redirect_uri") && form.get("redirect_uri") !== code.ru) throw new OAuthError("invalid_grant", "redirect_uri mismatch.");
    const verifier = form.get("code_verifier");
    if (!verifier || (await pkceChallenge(verifier)) !== code.cc) throw new OAuthError("invalid_grant", "PKCE verification failed.");
    return tokens(code.rt, code.u, code.cid);
  }
  if (grant === "refresh_token") {
    const sealed = await open<{ rt: string; u: string; cid: string }>("refresh", form.get("refresh_token"));
    if (!sealed) throw new OAuthError("invalid_grant", "The refresh token is invalid.");
    // the allowed account may have changed since
    if (!allowedUser(sealed.u)) throw new OAuthError("invalid_grant", `u/${sealed.u} may no longer use this server.`);
    return tokens(sealed.rt, sealed.u, sealed.cid);
  }
  throw new OAuthError("unsupported_grant_type", "Use authorization_code or refresh_token.");
}

async function tokens(redditRefreshToken: string, user: string, clientId: string) {
  return {
    access_token: await seal("access", { rt: redditRefreshToken, u: user, exp: Date.now() + ACCESS_TTL_S * 1000 } satisfies AccessGrant),
    token_type: "Bearer",
    expires_in: ACCESS_TTL_S,
    refresh_token: await seal("refresh", { rt: redditRefreshToken, u: user, cid: clientId }),
    scope: SCOPE,
  };
}

/** The grant behind a bearer token, or null when it is not one of ours, has expired or its account is no longer allowed. */
export async function verifyAccess(bearer: string | undefined): Promise<AccessGrant | null> {
  const grant = await open<AccessGrant>("access", bearer);
  return grant && grant.exp > Date.now() && allowedUser(grant.u) ? grant : null;
}
