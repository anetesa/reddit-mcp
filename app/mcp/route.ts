import { createMcpHandler, withMcpAuth } from "mcp-handler";
import { SCOPE, verifyAccess } from "@/lib/oauth";
import { REDDIT_INSTRUCTIONS, registerRedditTools } from "@/lib/redditTools";

const handler = createMcpHandler(registerRedditTools, {
  serverInfo: { name: "reddit", version: "0.1.0", title: "Reddit" } as { name: string; version: string },
  instructions: REDDIT_INSTRUCTIONS,
});

// Every request needs an access token from /oauth/token, whose sealed grant names an allowed Reddit account;
// without one the answer is a 401 whose WWW-Authenticate points the client at the OAuth metadata.
const authHandler = withMcpAuth(
  handler,
  async (_req, bearer) => {
    const grant = await verifyAccess(bearer);
    if (!grant) return undefined;
    return { token: bearer!, clientId: "reddit-mcp", scopes: [SCOPE], expiresAt: Math.floor(grant.exp / 1000), extra: { rt: grant.rt, u: grant.u } };
  },
  { required: true },
);

export { authHandler as GET, authHandler as POST, authHandler as DELETE };
