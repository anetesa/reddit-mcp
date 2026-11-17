import { OAuthError, origin, parseAuthorize, startSignIn } from "@/lib/oauth";

/** Checks the client's request and sends the browser on to Reddit's consent page. */
export async function GET(req: Request) {
  try {
    const request = await parseAuthorize(new URL(req.url).searchParams);
    return Response.redirect(await startSignIn(request, origin(req)), 302);
  } catch (e) {
    // a bad client_id or redirect_uri must not redirect anywhere: say so on the page
    if (e instanceof OAuthError) return new Response(`Sign-in: ${e.message}`, { status: 400, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
    throw e;
  }
}
