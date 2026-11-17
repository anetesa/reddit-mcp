import { CORS, OAuthError, register } from "@/lib/oauth";

/** RFC 7591 dynamic client registration, for clients that do not use a client metadata document. */
export async function POST(req: Request) {
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return new OAuthError("invalid_client_metadata", "The body must be JSON.").response();
  }
  try {
    return Response.json(await register(body), { status: 201, headers: CORS });
  } catch (e) {
    if (e instanceof OAuthError) return e.response();
    throw e;
  }
}

export function OPTIONS() {
  return new Response(null, { status: 204, headers: CORS });
}
