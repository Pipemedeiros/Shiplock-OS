/**
 * Data-changing surfaces the deep analysis does not read (Step 7D). The route
 * inventory reads App Router route handlers and Pages API routes. Next.js
 * apps also change data through server actions (`"use server"`) and tRPC
 * procedures; measured 2026-09-24 on the pinned corpus: corpus-c 66 files
 * with server actions, corpus-af 48 tRPC files, corpus-e 40. Counting them lets
 * Coverage say they were not read, instead of an audit looking complete.
 */
const IGNORED = /(^|\/)(node_modules|\.next|dist|build|vendor)\//;
const CODE = /\.[cm]?[jt]sx?$/;
// A directive: the first statement of the file, or the first statement of a function body.
const USE_SERVER = /(^|\n)\s*["']use server["'];?\s*(\n|$)|\{\s*["']use server["'];?/;
const TRPC = /\b(?:publicProcedure|protectedProcedure|authedProcedure|adminProcedure|createTRPCRouter|t\.procedure|initTRPC)\b/;

export function countUnanalyzedSurfaces(files: { path: string; content: string }[]): { serverActionFiles: number; trpcFiles: number } {
  let serverActionFiles = 0, trpcFiles = 0;
  for (const file of files) {
    if (IGNORED.test(file.path) || !CODE.test(file.path)) continue;
    if (USE_SERVER.test(file.content)) serverActionFiles++;
    if (TRPC.test(file.content)) trpcFiles++;
  }
  return { serverActionFiles, trpcFiles };
}
