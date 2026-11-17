import { beforeAll, describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/server";
import { seal } from "../lib/crypto";
import { token, verifyAccess } from "../lib/oauth";
import { confirmationFor, confirmationMatches, filterPosts, parseThing, registerRedditTools, type RawPost } from "../lib/redditTools";

beforeAll(() => {
  process.env.HUB_SECRET = "test-secret-test-secret-test-secret-123";
  process.env.REDDIT_ALLOWED_USER = "Owner_Name";
});

const owner = { rt: "reddit-refresh", u: "Owner_Name" };

describe("posting needs a confirmation of the exact preview", () => {
  it("accepts the token only for the same text, parent and account", async () => {
    const t = await confirmationFor(owner, "t3_abc", "Hello there");
    expect(await confirmationMatches(t, owner, "t3_abc", "Hello there")).toBe(true);
    expect(await confirmationMatches(t, owner, "t3_abc", "Hello there!")).toBe(false);
    expect(await confirmationMatches(t, owner, "t1_xyz", "Hello there")).toBe(false);
    expect(await confirmationMatches(t, { ...owner, u: "someone" }, "t3_abc", "Hello there")).toBe(false);
    expect(await confirmationMatches("forged.token", owner, "t3_abc", "Hello there")).toBe(false);
  });

  it("rejects an expired confirmation", async () => {
    const expired = await seal("post", { p: "t3_abc", h: "x", u: owner.u, exp: Date.now() - 1 });
    expect(await confirmationMatches(expired, owner, "t3_abc", "Hello")).toBe(false);
  });
});

describe("parseThing", () => {
  it("reads ids, fullnames and links", () => {
    expect(parseThing("1xxwtaq")).toEqual({ fullname: "t3_1xxwtaq", postId: "1xxwtaq" });
    expect(parseThing("t1_abc")).toEqual({ fullname: "t1_abc", postId: "" });
    expect(parseThing("https://www.reddit.com/r/x/comments/1xxwtaq/some_title/")).toEqual({ fullname: "t3_1xxwtaq", postId: "1xxwtaq" });
    expect(parseThing("https://www.reddit.com/r/x/comments/1xxwtaq/some_title/ocj2k1/")).toEqual({ fullname: "t1_ocj2k1", postId: "1xxwtaq" });
    expect(() => parseThing("not a link!")).toThrow();
  });
});

describe("filterPosts", () => {
  const now = 1_800_000_000_000;
  const post = (o: Partial<RawPost>): RawPost => ({
    id: "a", name: "t3_a", subreddit: "s", title: "t", author: "x", score: 1, num_comments: 0,
    created_utc: now / 1000 - 3600, permalink: "/r/s/comments/a/", ...o,
  });
  it("keeps young, quiet, open posts", () => {
    const posts = [post({ id: "ok" }), post({ id: "old", created_utc: now / 1000 - 10 * 3600 }), post({ id: "busy", num_comments: 50 }), post({ id: "locked", locked: true }), post({ id: "pinned", stickied: true })];
    expect(filterPosts(posts, { maxAgeHours: 3, maxComments: 10 }, now).map((p) => p.id)).toEqual(["ok"]);
  });
});

describe("tokens", () => {
  it("issue access tokens only to the allowed account", async () => {
    const access = await seal("access", { rt: "r", u: "owner_name", exp: Date.now() + 60_000 });
    expect((await verifyAccess(access))?.u).toBe("owner_name");
    expect(await verifyAccess(await seal("access", { rt: "r", u: "intruder", exp: Date.now() + 60_000 }))).toBeNull();
    expect(await verifyAccess(await seal("access", { rt: "r", u: "owner_name", exp: Date.now() - 1 }))).toBeNull();
    // a refresh token or a code is not an access token
    expect(await verifyAccess(await seal("refresh", { rt: "r", u: "owner_name", exp: Date.now() + 60_000 }))).toBeNull();
  });

  it("refuses to refresh for an account that is no longer allowed", async () => {
    const refresh = await seal("refresh", { rt: "r", u: "intruder", cid: "c" });
    await expect(token(new URLSearchParams({ grant_type: "refresh_token", refresh_token: refresh }))).rejects.toThrow(/no longer/);
  });
});

describe("tool listing", () => {
  it("gives every tool a title in its annotations, a read/write hint and described fields", () => {
    const server = new McpServer({ name: "t", version: "0" });
    const seen: { name: string; config: any }[] = [];
    const original = server.registerTool.bind(server);
    server.registerTool = ((name: string, config: any, handler: any) => {
      seen.push({ name, config });
      return original(name, config, handler);
    }) as typeof server.registerTool;
    registerRedditTools(server);
    expect(seen.map((s) => s.name)).toContain("reddit_post_comment");
    const bad: string[] = [];
    for (const { name, config } of seen) {
      expect(config.annotations.title, name).toBe(config.title);
      expect(typeof config.annotations.readOnlyHint, name).toBe("boolean");
      if (/reddit_/.test(config.description)) bad.push(name);
      for (const [field, schema] of Object.entries<any>(config.inputSchema.shape)) if (!schema.description) bad.push(`${name}.${field}`);
    }
    expect(bad).toEqual([]);
    expect(seen.find((s) => s.name === "reddit_post_comment")!.config.annotations.readOnlyHint).toBe(false);
  });
});
