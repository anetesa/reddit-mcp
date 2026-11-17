import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { open, seal } from "./crypto";
import { api, RedditError } from "./reddit";

export const REDDIT_INSTRUCTIONS = `Reddit as the owner's own account: find posts worth answering, read threads and subreddit rules, follow
the replies and score of the owner's comments, and post comments.
Posting is two steps on purpose: reddit_post_comment without confirmToken only shows a preview and returns a token;
show the owner the exact text and where it goes, and call it again with that token only after they say yes in the
chat. Never post a text the owner has not seen in its final form, and follow each subreddit's rules.`;

/** What a tool sees of its caller: the Reddit refresh token and account sealed in the bearer token. */
export interface Caller {
  rt: string;
  u: string;
}

type Ctx = { authInfo?: { extra?: Record<string, unknown> } };
export const callerOf = (ctx: unknown): Caller => {
  const extra = (ctx as Ctx).authInfo?.extra;
  if (!extra || typeof extra.rt !== "string" || typeof extra.u !== "string") throw new RedditError("Not signed in.", 401);
  return { rt: extra.rt, u: extra.u };
};

async function run(work: () => Promise<unknown>) {
  try {
    const result = await work();
    return { content: [{ type: "text" as const, text: typeof result === "string" ? result : JSON.stringify(result, null, 2) }] };
  } catch (e) {
    if (e instanceof RedditError) return { content: [{ type: "text" as const, text: e.message }], isError: true };
    throw e;
  }
}

// ── Reddit's listing shapes, only the fields used ───────────────────────────
interface Thing<T> {
  kind: string;
  data: T;
}
interface Listing<T> {
  data: { children: Thing<T>[]; after?: string | null };
}
export interface RawPost {
  id: string;
  name: string;
  subreddit: string;
  title: string;
  author: string;
  score: number;
  num_comments: number;
  created_utc: number;
  permalink: string;
  selftext?: string;
  url?: string;
  is_self?: boolean;
  link_flair_text?: string | null;
  over_18?: boolean;
  locked?: boolean;
  stickied?: boolean;
}
export interface RawComment {
  id: string;
  name: string;
  author: string;
  body?: string;
  score?: number;
  created_utc?: number;
  permalink?: string;
  link_title?: string;
  subreddit?: string;
  parent_id?: string;
  replies?: Listing<RawComment> | "";
  new?: boolean;
  was_comment?: boolean;
  context?: string;
}

const hoursSince = (utc: number, now = Date.now()) => Math.round(((now / 1000 - utc) / 3600) * 10) / 10;
const link = (permalink: string) => `https://www.reddit.com${permalink}`;

export function summarizePost(p: RawPost, now = Date.now()) {
  return {
    id: p.id,
    subreddit: p.subreddit,
    title: p.title,
    author: p.author,
    score: p.score,
    comments: p.num_comments,
    ageHours: hoursSince(p.created_utc, now),
    flair: p.link_flair_text ?? null,
    text: p.is_self ? (p.selftext ?? "").slice(0, 400) : null,
    linkTo: p.is_self ? null : (p.url ?? null),
    locked: !!p.locked,
    url: link(p.permalink),
  };
}

/** Posts that can still take a comment, young enough and quiet enough. */
export function filterPosts(posts: RawPost[], opts: { maxAgeHours?: number; maxComments?: number; minScore?: number }, now = Date.now()) {
  return posts.filter(
    (p) =>
      !p.locked &&
      !p.stickied &&
      (opts.maxAgeHours == null || hoursSince(p.created_utc, now) <= opts.maxAgeHours) &&
      (opts.maxComments == null || p.num_comments <= opts.maxComments) &&
      (opts.minScore == null || p.score >= opts.minScore),
  );
}

/** A post or comment id from an id ("abc12", "t3_abc12") or a Reddit URL; the fullname for the API. */
export function parseThing(input: string): { fullname: string; postId: string } {
  const value = input.trim();
  const url = value.match(/comments\/([a-z0-9]+)(?:\/[^/]*\/([a-z0-9]+))?/i);
  if (url) return url[2] ? { fullname: `t1_${url[2]}`, postId: url[1]! } : { fullname: `t3_${url[1]}`, postId: url[1]! };
  const full = value.match(/^(t[13])_([a-z0-9]+)$/i);
  if (full) return { fullname: `${full[1]!.toLowerCase()}_${full[2]}`, postId: full[1]!.toLowerCase() === "t3" ? full[2]! : "" };
  if (/^[a-z0-9]+$/i.test(value)) return { fullname: `t3_${value}`, postId: value };
  throw new RedditError(`"${input}" is not a Reddit post or comment id or link.`, 400);
}

export function flattenComments(children: Thing<RawComment>[], maxDepth: number, depth = 0, out: object[] = []) {
  for (const child of children) {
    if (child.kind !== "t1") continue;
    const c = child.data;
    out.push({ id: c.id, depth, author: c.author, score: c.score, ageHours: c.created_utc ? hoursSince(c.created_utc) : null, text: c.body });
    if (depth + 1 < maxDepth && c.replies && typeof c.replies === "object") flattenComments(c.replies.data.children, maxDepth, depth + 1, out);
  }
  return out;
}

const textHash = async (text: string) =>
  Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))).toString("base64url");

interface PostConfirmation {
  p: string;
  h: string;
  u: string;
  exp: number;
}
const CONFIRM_TTL_MS = 30 * 60_000;

export async function confirmationFor(caller: Caller, parent: string, text: string) {
  return seal("post", { p: parent, h: await textHash(text), u: caller.u, exp: Date.now() + CONFIRM_TTL_MS } satisfies PostConfirmation);
}

/** True only for a token from a preview of this very text, to this parent, by this account, not yet expired. */
export async function confirmationMatches(token: string, caller: Caller, parent: string, text: string) {
  const c = await open<PostConfirmation>("post", token);
  return !!c && c.exp > Date.now() && c.u === caller.u && c.p === parent && c.h === (await textHash(text));
}

const readOnly = { readOnlyHint: true, destructiveHint: false, openWorldHint: true };
const subredditName = z
  .string()
  .regex(/^(r\/)?[A-Za-z0-9_]{2,21}$/)
  .transform((s) => s.replace(/^r\//, ""));

export function registerRedditTools(server: McpServer) {
  const register = server.registerTool.bind(server);
  server.registerTool = ((name: string, config: { title?: string; annotations?: object }, handler: unknown) =>
    register(name, { ...config, annotations: { title: config.title, ...config.annotations } } as never, handler as never)) as typeof server.registerTool;

  server.registerTool(
    "reddit_find_posts",
    {
      title: "Find posts",
      description:
        "Latest, rising or hot posts from up to 10 subreddits, filtered to ones still worth answering: open, not pinned, " +
        "younger than maxAgeHours, with at most maxComments comments. Newest first, with score, comment count, age, " +
        "flair and the start of the text.",
      inputSchema: z.object({
        subreddits: z.array(subredditName).min(1).max(10).describe('Names without r/, e.g. ["NoStupidQuestions", "MechanicAdvice"]'),
        sort: z.enum(["new", "rising", "hot"]).optional().describe("new by default"),
        maxAgeHours: z.number().positive().optional().describe("Only posts at most this old"),
        maxComments: z.number().int().nonnegative().optional().describe("Only posts with at most this many comments"),
        minScore: z.number().int().optional().describe("Only posts with at least this score"),
        perSubreddit: z.number().int().min(1).max(100).optional().describe("Posts read from each subreddit before filtering; 25 by default"),
      }),
      annotations: readOnly,
    },
    async ({ subreddits, sort = "new", maxAgeHours, maxComments, minScore, perSubreddit = 25 }, ctx) =>
      run(async () => {
        const caller = callerOf(ctx);
        const results = await Promise.allSettled(
          subreddits.map((s) => api<Listing<RawPost>>(caller.rt, `/r/${s}/${sort}?limit=${perSubreddit}`)),
        );
        const posts = results.flatMap((r) => (r.status === "fulfilled" ? r.value.data.children.map((c) => c.data) : []));
        const failed = results.flatMap((r, i) => (r.status === "rejected" ? [`r/${subreddits[i]}: ${(r.reason as Error).message}`] : []));
        const found = filterPosts(posts, { maxAgeHours, maxComments, minScore })
          .sort((a, b) => b.created_utc - a.created_utc)
          .map((p) => summarizePost(p));
        return failed.length ? { posts: found, failed } : found;
      }),
  );

  server.registerTool(
    "reddit_search_posts",
    {
      title: "Search posts",
      description: "Searches Reddit posts by words, everywhere or in one subreddit, within a time window.",
      inputSchema: z.object({
        query: z.string().min(1).describe("Words to search for"),
        subreddit: subredditName.optional().describe("Only this subreddit"),
        sort: z.enum(["relevance", "new", "top", "comments"]).optional().describe("relevance by default"),
        time: z.enum(["hour", "day", "week", "month", "year", "all"]).optional().describe("day by default"),
        limit: z.number().int().min(1).max(100).optional().describe("25 by default"),
      }),
      annotations: readOnly,
    },
    async ({ query, subreddit, sort = "relevance", time = "day", limit = 25 }, ctx) =>
      run(async () => {
        const caller = callerOf(ctx);
        const params = new URLSearchParams({ q: query, sort, t: time, limit: String(limit), type: "link" });
        if (subreddit) params.set("restrict_sr", "1");
        const listing = await api<Listing<RawPost>>(caller.rt, `${subreddit ? `/r/${subreddit}` : ""}/search?${params}`);
        return listing.data.children.map((c) => summarizePost(c.data));
      }),
  );

  server.registerTool(
    "reddit_get_post",
    {
      title: "Read a thread",
      description: "A post in full with its comments as a flat list (each with its id, depth, author, score, age and text), best first.",
      inputSchema: z.object({
        post: z.string().describe("Post id or link"),
        comments: z.number().int().min(0).max(500).optional().describe("Most comments to read; 100 by default"),
        depth: z.number().int().min(1).max(10).optional().describe("Reply levels to include; 4 by default"),
      }),
      annotations: readOnly,
    },
    async ({ post, comments = 100, depth = 4 }, ctx) =>
      run(async () => {
        const caller = callerOf(ctx);
        const { postId } = parseThing(post);
        if (!postId) throw new RedditError("Give the post's id or link, not a comment's id.", 400);
        const [postListing, commentListing] = await api<[Listing<RawPost>, Listing<RawComment>]>(
          caller.rt,
          `/comments/${postId}?limit=${comments}&depth=${depth}&sort=confidence`,
        );
        const p = postListing.data.children[0]?.data;
        if (!p) throw new RedditError(`No post ${postId}.`, 404);
        return { ...summarizePost(p), text: p.selftext ?? "", comments: flattenComments(commentListing.data.children, depth) };
      }),
  );

  server.registerTool(
    "reddit_get_rules",
    {
      title: "Subreddit rules",
      description: "A subreddit's rules and its description, to check before commenting.",
      inputSchema: z.object({ subreddit: subredditName.describe("Name without r/") }),
      annotations: readOnly,
    },
    async ({ subreddit }, ctx) =>
      run(async () => {
        const caller = callerOf(ctx);
        const [rules, about] = await Promise.all([
          api<{ rules: { short_name: string; description: string; kind: string }[] }>(caller.rt, `/r/${subreddit}/about/rules`),
          api<{ data: { public_description?: string; subscribers?: number } }>(caller.rt, `/r/${subreddit}/about`),
        ]);
        return {
          subreddit,
          subscribers: about.data.subscribers ?? null,
          about: about.data.public_description ?? "",
          rules: rules.rules.map((r) => ({ rule: r.short_name, appliesTo: r.kind, text: r.description })),
        };
      }),
  );

  server.registerTool(
    "reddit_my_activity",
    {
      title: "My comments and replies",
      description:
        "The owner's account: karma, recent comments with their score and thread, and replies to the owner's comments " +
        "and posts from the inbox (unread ones marked).",
      inputSchema: z.object({ limit: z.number().int().min(1).max(100).optional().describe("Most comments and replies each; 25 by default") }),
      annotations: readOnly,
    },
    async ({ limit = 25 }, ctx) =>
      run(async () => {
        const caller = callerOf(ctx);
        const [me, comments, inbox] = await Promise.all([
          api<{ name: string; link_karma: number; comment_karma: number; created_utc: number }>(caller.rt, "/api/v1/me"),
          api<Listing<RawComment>>(caller.rt, `/user/${caller.u}/comments?limit=${limit}&sort=new`),
          api<Listing<RawComment>>(caller.rt, `/message/inbox?limit=${limit}`),
        ]);
        return {
          account: { name: me.name, commentKarma: me.comment_karma, postKarma: me.link_karma, ageDays: Math.floor(hoursSince(me.created_utc) / 24) },
          comments: comments.data.children.map(({ data: c }) => ({
            id: c.id,
            subreddit: c.subreddit,
            thread: c.link_title,
            score: c.score,
            ageHours: c.created_utc ? hoursSince(c.created_utc) : null,
            text: (c.body ?? "").slice(0, 300),
            url: c.permalink ? link(c.permalink) : null,
          })),
          replies: inbox.data.children
            .filter(({ data: m }) => m.was_comment)
            .map(({ data: m }) => ({
              id: m.id,
              from: m.author,
              thread: m.link_title,
              unread: !!m.new,
              ageHours: m.created_utc ? hoursSince(m.created_utc) : null,
              text: m.body,
              url: m.context ? link(m.context) : null,
            })),
        };
      }),
  );

  server.registerTool(
    "reddit_post_comment",
    {
      title: "Post a comment",
      description:
        "Comments on a post or replies to a comment as the owner. Without confirmToken nothing is posted: it returns a " +
        "preview with the thread, the parent and the exact text, and a confirmToken valid for 30 minutes for this text and " +
        "parent only. With the token it posts and returns the new comment's link.",
      inputSchema: z.object({
        parent: z.string().describe("The post or comment to answer: id, t3_/t1_ fullname or link"),
        text: z.string().min(1).max(10_000).describe("The comment, in Reddit Markdown"),
        confirmToken: z.string().optional().describe("The token from this exact preview; left out to get the preview"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async ({ parent, text, confirmToken }, ctx) =>
      run(async () => {
        const caller = callerOf(ctx);
        const { fullname } = parseThing(parent);
        if (!confirmToken) {
          const info = await api<Listing<RawPost & RawComment>>(caller.rt, `/api/info?id=${fullname}`);
          const target = info.data.children[0]?.data;
          if (!target) throw new RedditError(`Nothing found for ${fullname}.`, 404);
          if (target.locked) throw new RedditError("That thread is locked: it takes no comments.", 400);
          return {
            preview: "Not posted yet. Show this to the owner; post only after they approve, with confirmToken.",
            as: `u/${caller.u}`,
            subreddit: target.subreddit,
            replyingTo: fullname.startsWith("t3_")
              ? { post: target.title, author: target.author }
              : { comment: (target.body ?? "").slice(0, 300), author: target.author },
            text,
            confirmToken: await confirmationFor(caller, fullname, text),
          };
        }
        if (!(await confirmationMatches(confirmToken, caller, fullname, text))) {
          throw new RedditError("The confirmToken does not match this text and parent, or has expired. Preview again.", 400);
        }
        const result = await api<{ json: { errors: string[][]; data?: { things: Thing<RawComment>[] } } }>(caller.rt, "/api/comment", {
          api_type: "json",
          thing_id: fullname,
          text,
        });
        if (result.json.errors.length) throw new RedditError(`Reddit refused the comment: ${result.json.errors.map((e) => e.join(" ")).join("; ")}`, 400);
        const posted = result.json.data?.things[0]?.data;
        return { posted: true, id: posted?.id, url: posted?.permalink ? link(posted.permalink) : null };
      }),
  );
}
