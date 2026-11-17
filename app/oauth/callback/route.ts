import { finishSignIn, OAuthError, origin } from "@/lib/oauth";

/** Reddit's redirect after the consent page: back to the MCP client with a code, or with the reason it failed. */
export async function GET(req: Request) {
  try {
    const target = await finishSignIn(new URL(req.url).searchParams, origin(req));
    return new Response(null, { status: 302, headers: { Location: target, "Cache-Control": "no-store" } });
  } catch (e) {
    if (e instanceof OAuthError) return new Response(`Sign-in: ${e.message}`, { status: 400, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
    throw e;
  }
}
