import { generateProtectedResourceMetadata, metadataCorsOptionsRequestHandler } from "mcp-handler";
import { CORS, SCOPE, origin } from "@/lib/oauth";

// RFC 9728, at /.well-known/oauth-protected-resource and /.well-known/oauth-protected-resource/mcp:
// the MCP endpoint is guarded by this same origin's authorization server.
export function GET(req: Request) {
  const issuer = origin(req);
  const metadata = generateProtectedResourceMetadata({
    authServerUrls: [issuer],
    resourceUrl: `${issuer}/mcp`,
    additionalMetadata: { scopes_supported: [SCOPE], resource_name: "Reddit" },
  });
  return Response.json(metadata, { headers: { ...CORS, "Cache-Control": "max-age=3600" } });
}

export const OPTIONS = metadataCorsOptionsRequestHandler();
