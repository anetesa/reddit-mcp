// Reddit's OAuth and API, as the owner's own Reddit app (a "web app" at reddit.com/prefs/apps). The server keeps no
// tokens: the owner's Reddit refresh token travels sealed inside the MCP client's tokens, and an access token for
// it is cached here for its hour of life.

export const REDDIT_SCOPES = ["identity", "read", "history", "submit", "privatemessages"];
const USER_AGENT = "web:reddit-mcp:0.1.0 (personal assistant tools)";

export class RedditError extends Error {
  constructor(
    message: string,
    readonly status = 502,
  ) {
    super(message);
  }
}

function app() {
  const id = process.env.REDDIT_CLIENT_ID;
  const secret = process.env.REDDIT_CLIENT_SECRET;
  if (!id || !secret) throw new RedditError("REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET are not set.", 500);
  return { id, secret };
}

/** Only this Reddit account may connect; nobody when it is not set. */
export function allowedUser(name: string): boolean {
  const allowed = process.env.REDDIT_ALLOWED_USER?.trim().toLowerCase();
  return !!allowed && name.toLowerCase() === allowed;
}

export function authorizeUrl(redirectUri: string, state: string): string {
  const url = new URL("https://www.reddit.com/api/v1/authorize");
  url.search = new URLSearchParams({
    client_id: app().id,
    response_type: "code",
    state,
    redirect_uri: redirectUri,
    duration: "permanent",
    scope: REDDIT_SCOPES.join(" "),
  }).toString();
  return url.toString();
}

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  error?: string;
}

async function tokenRequest(body: Record<string, string>): Promise<TokenResponse> {
  const { id, secret } = app();
  const response = await fetch("https://www.reddit.com/api/v1/access_token", {
    method: "POST",
    headers: {
      Authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`,
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": USER_AGENT,
    },
    body: new URLSearchParams(body),
  });
  const json = (await response.json().catch(() => ({}))) as TokenResponse;
  if (!response.ok || json.error || !json.access_token) {
    throw new RedditError(`Reddit sign-in failed: ${json.error ?? `HTTP ${response.status}`}`, 401);
  }
  return json;
}

const accessCache = new Map<string, { token: string; until: number }>();

function remember(refreshToken: string, token: TokenResponse) {
  accessCache.set(refreshToken, { token: token.access_token!, until: Date.now() + ((token.expires_in ?? 3600) - 60) * 1000 });
}

/** Exchanges the code from Reddit's consent page; returns the refresh token and the account name. */
export async function exchangeCode(code: string, redirectUri: string): Promise<{ refreshToken: string; user: string }> {
  const token = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: redirectUri });
  if (!token.refresh_token) throw new RedditError("Reddit gave no refresh token.", 401);
  remember(token.refresh_token, token);
  const me = await api<{ name: string }>(token.refresh_token, "/api/v1/me");
  return { refreshToken: token.refresh_token, user: me.name };
}

async function accessToken(refreshToken: string): Promise<string> {
  const cached = accessCache.get(refreshToken);
  if (cached && cached.until > Date.now()) return cached.token;
  const token = await tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken });
  remember(refreshToken, token);
  return token.access_token!;
}

/** A call to oauth.reddit.com as the owner. [form] makes it a POST. */
export async function api<T>(refreshToken: string, path: string, form?: Record<string, string>): Promise<T> {
  const url = new URL(path, "https://oauth.reddit.com");
  url.searchParams.set("raw_json", "1");
  const response = await fetch(url, {
    method: form ? "POST" : "GET",
    headers: {
      Authorization: `Bearer ${await accessToken(refreshToken)}`,
      "User-Agent": USER_AGENT,
      ...(form ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
    },
    body: form ? new URLSearchParams(form) : undefined,
  });
  if (response.status === 429) {
    const wait = response.headers.get("x-ratelimit-reset");
    throw new RedditError(`Reddit's rate limit: try again in ${wait ?? "a few"} seconds.`, 429);
  }
  if (response.status === 404) throw new RedditError(`Not found on Reddit: ${path}`, 404);
  if (response.status === 403) throw new RedditError(`Reddit refused access to ${path} (private, banned or quarantined).`, 403);
  if (!response.ok) throw new RedditError(`Reddit answered HTTP ${response.status} for ${path}.`);
  return (await response.json()) as T;
}
