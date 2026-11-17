import { metadataCorsOptionsRequestHandler } from "mcp-handler";
import { CORS, authorizationServerMetadata, origin } from "@/lib/oauth";

// RFC 8414. Some clients also look under /.well-known/openid-configuration, which re-exports this.
export function GET(req: Request) {
  return Response.json(authorizationServerMetadata(origin(req)), { headers: { ...CORS, "Cache-Control": "max-age=3600" } });
}

export const OPTIONS = metadataCorsOptionsRequestHandler();
