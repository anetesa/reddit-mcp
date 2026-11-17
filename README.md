# Reddit MCP

A private MCP server at `https://reddit.brelio.pl/mcp` that lets an assistant use Reddit as its owner: find posts
worth answering, read threads and subreddit rules, follow the replies and score of the owner's comments, and post
comments after the owner approves the exact text.

- Sign-in is Reddit's own OAuth with the owner's Reddit app; only `REDDIT_ALLOWED_USER` gets through.
- No database: the owner's Reddit refresh token travels sealed (AES-256-GCM, `HUB_SECRET`) inside the MCP client's tokens.
- Posting is two calls: a preview that returns a confirm token bound to that text, parent and account, then the post.

Environment: `HUB_SECRET` (32+ random characters), `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET`, `REDDIT_ALLOWED_USER`.
The Reddit app is a "web app" with the redirect URI `https://reddit.brelio.pl/oauth/callback`.

```bash
npm test && npm run typecheck && npm run build
```
