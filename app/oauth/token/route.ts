import { CORS, OAuthError, token } from "@/lib/oauth";

export async function POST(req: Request) {
  const type = req.headers.get("content-type") ?? "";
  // the spec says form-encoded; some clients send JSON
  const form = type.includes("application/json")
    ? new URLSearchParams(Object.entries((await req.json()) as Record<string, string>))
    : new URLSearchParams(await req.text());
  try {
    return Response.json(await token(form), { headers: { ...CORS, "Cache-Control": "no-store", Pragma: "no-cache" } });
  } catch (e) {
    if (e instanceof OAuthError) return e.response();
    throw e;
  }
}

export function OPTIONS() {
  return new Response(null, { status: 204, headers: CORS });
}
