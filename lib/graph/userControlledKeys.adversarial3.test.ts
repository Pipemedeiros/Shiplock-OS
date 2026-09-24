import { describe, expect, it } from "vitest";
import { findUserControlledDeletes } from "./userControlledKeys";

// Third adversarial round for Step 7F. Each case asserts the correct security
// answer, not the rule's current behaviour, and differs in shape from the
// cases in userControlledKeys.test.ts and the first two adversarial files.
// Synthetic fixtures only.
const one = (body: string, entry = "remove") => findUserControlledDeletes(body, entry);

describe("findUserControlledDeletes round 3: false negatives (real caller-controlled deletions)", () => {
  // FN: Next.js 15 dynamic route params are a promise; the URL segment is caller-controlled.
  it("awaited dynamic route params as the key", () => {
    expect(one(`export async function DELETE(req: Request, { params }: { params: Promise<{ key: string }> }) {\n  const { key } = await params;\n  await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));\n  return new Response(null, { status: 204 });\n}`, "DELETE").length).toBeGreaterThan(0);
  });

  // FN: R2/S3 bulk deletion takes the keys inside Delete.Objects, mapped from caller input.
  it("DeleteObjectsCommand with caller keys mapped into Objects", () => {
    expect(one(`const { keys } = await req.json();\nawait r2.send(new DeleteObjectsCommand({ Bucket: BUCKET, Delete: { Objects: keys.map((Key: string) => ({ Key })) } }));`).length).toBeGreaterThan(0);
  });

  // FN: a recursive rm of a caller-named directory wipes a whole tree.
  it("fs.promises.rm recursive on a caller-named directory", () => {
    expect(one(`await fs.promises.rm(path.join(WORKSPACES_DIR, parsedInput.workspace), { recursive: true, force: true });`).length).toBeGreaterThan(0);
  });

  // FN: the row owner is compared with a userId the caller sent in the body, not the session.
  it("row owner compared with a caller-sent userId", () => {
    expect(one(`const { fileId, userId } = await req.json();\nconst file = await prisma.file.findUnique({ where: { id: fileId } });\nif (!file || file.userId !== userId) return new Response("Forbidden", { status: 403 });\nawait deleteObject(file.key);`).length).toBeGreaterThan(0);
  });

  // FN: an owner-filtered lookup runs but its result is never checked, so it guards nothing.
  it("owner-filtered lookup whose result is ignored", () => {
    expect(one(`const key = parsedInput.key;\nawait prisma.file.findFirst({ where: { key, userId: ctx.user.id } });\nawait deleteObject(key);`).length).toBeGreaterThan(0);
  });

  // FN: the ownership assertion throws inside a try whose catch only logs, so execution continues.
  it("assert helper inside a try/catch that swallows the error", () => {
    expect(one(`const key = parsedInput.key;\ntry {\n  assertOwnedKey(key, ctx.user.id);\n} catch (err) {\n  console.error("ownership check failed", err);\n}\nawait deleteObject(key);`).length).toBeGreaterThan(0);
  });

  // FN: the ownership check runs after the object is already gone.
  it("ownership check placed after the deletion", () => {
    expect(one(`const key = parsedInput.key;\nawait deleteObject(key);\nif (!key.startsWith(\`users/\${ctx.user.id}/\`)) throw new Error("forbidden");\nreturn { ok: true };`).length).toBeGreaterThan(0);
  });

  // FN: the guard only runs when a caller flag is unset; force: true skips it.
  it("guard nested under a caller-controlled flag", () => {
    expect(one(`const { key, force } = parsedInput;\nif (!force) {\n  if (!key.startsWith(\`users/\${ctx.user.id}/\`)) throw new Error("forbidden");\n}\nawait deleteObject(key);`).length).toBeGreaterThan(0);
  });

  // FN: better-auth lets the user set their own image URL, so it can point at another user's blob.
  it("better-auth session.user.image passed to Vercel Blob del", () => {
    expect(one(`const session = await auth.api.getSession({ headers: await headers() });\nif (!session) return { error: "unauthorized" };\nawait del(session.user.image!);`).length).toBeGreaterThan(0);
  });

  // FN: a query parameter read through new URL(req.url) builds the GCS object name.
  it("GCS delete with a name from new URL(req.url).searchParams", () => {
    expect(one(`const { searchParams } = new URL(req.url);\nconst name = searchParams.get("name");\nawait storage.bucket(BUCKET).file(\`exports/\${name}\`).delete();`, "DELETE").length).toBeGreaterThan(0);
  });

  // FN: next-safe-action destructures parsedInput in the callback's own parameter list.
  it("next-safe-action callback destructuring parsedInput", () => {
    expect(one(`"use server";\nexport const deleteAttachment = authActionClient\n  .schema(deleteSchema)\n  .action(async ({ parsedInput: { fileKey }, ctx }) => {\n    await utapi.deleteFiles(fileKey);\n    return { ok: true };\n  });`, "deleteAttachment").length).toBeGreaterThan(0);
  });

  // FN: authentication is not ownership; any signed-in user can delete any blob.
  it("session presence check with no ownership check", () => {
    expect(one(`const session = await auth();\nif (!session?.user) return new Response("Unauthorized", { status: 401 });\nconst body = await req.json();\nawait del(body.url);`).length).toBeGreaterThan(0);
  });

  // FN: the command input is built as a separate params object before being sent.
  it("DeleteObjectCommand params object built beforehand", () => {
    expect(one(`const body = await req.json();\nconst params = { Bucket: BUCKET, Key: body.key };\nawait s3.send(new DeleteObjectCommand(params));`).length).toBeGreaterThan(0);
  });
});

describe("findUserControlledDeletes round 3: false positives (safe code)", () => {
  // FP: the DB delete itself is owner-scoped and throws if no row matches; the key comes from that row.
  it("key from an owner-scoped prisma delete", () => {
    expect(one(`const file = await prisma.file.delete({ where: { id: parsedInput.id, userId: ctx.user.id } });\nawait deleteObject(file.key);`)).toEqual([]);
  });

  // FP: Supabase read filtered by the authenticated user's id before removing the stored path.
  it("supabase row filtered by owner_id from getUser()", () => {
    expect(one(`const { data: { user } } = await supabase.auth.getUser();\nif (!user) return new Response(null, { status: 401 });\nconst { id } = await req.json();\nconst { data: doc } = await supabaseAdmin.from("documents").select("path").eq("id", id).eq("owner_id", user.id).single();\nif (!doc) return new Response(null, { status: 404 });\nawait supabaseAdmin.storage.from("documents").remove([doc.path]);`)).toEqual([]);
  });

  // FP: drizzle row compared with the lucia session user before UploadThing deletion.
  it("drizzle row owner compared with lucia validateRequest user", () => {
    expect(one(`const { user } = await validateRequest();\nif (!user) return { error: "unauthorized" };\nconst upload = await db.query.uploads.findFirst({ where: eq(uploads.id, parsedInput.id) });\nif (!upload || upload.userId !== user.id) return { error: "not found" };\nawait utapi.deleteFiles(upload.key);`)).toEqual([]);
  });

  // FP: the caller's value only selects a literal prefix from a fixed map; the rest is the caller's id.
  it("literal map lookup for the prefix plus the caller's id", () => {
    expect(one(`const PREFIX = { avatar: "avatars", banner: "banners" } as const;\nconst prefix = PREFIX[parsedInput.kind as keyof typeof PREFIX];\nif (!prefix) throw new Error("bad kind");\nawait deleteObject(\`\${prefix}/\${ctx.user.id}.png\`);`)).toEqual([]);
  });

  // FP: Map.delete on a local in-memory map is not storage deletion.
  it("delete on a local Map", () => {
    expect(one(`const pending = new Map(parsedInput.items.map((i: Item) => [i.key, i]));\npending.delete(parsedInput.skipKey);\nreturn [...pending.values()];`)).toEqual([]);
  });

  // FP: deleting a cookie by caller name only affects the caller's own browser.
  it("cookies().delete with a caller-chosen name", () => {
    expect(one(`"use server";\nexport async function dismiss(name: string) {\n  (await cookies()).delete(name);\n}`, "dismiss")).toEqual([]);
  });

  // FP: the unlinked path is a server-generated temp file; the caller only supplied its contents.
  it("unlink of a server-generated temp file in finally", () => {
    expect(one(`const file = formData.get("file") as File;\nconst tmp = path.join(os.tmpdir(), \`\${randomUUID()}.pdf\`);\ntry {\n  await writeFile(tmp, Buffer.from(await file.arrayBuffer()));\n  await convert(tmp);\n} finally {\n  await fs.promises.unlink(tmp);\n}`)).toEqual([]);
  });

  // FP: the caller picks the project, but the query is filtered by the project's owner being the caller.
  it("loop over rows filtered by a nested relation owner", () => {
    expect(one(`const files = await prisma.file.findMany({ where: { projectId: parsedInput.projectId, project: { ownerId: ctx.user.id } } });\nfor (const f of files) {\n  await deleteObject(f.key);\n}`)).toEqual([]);
  });

  // FP: caller keys are intersected with an owner-filtered query and only the returned rows are deleted.
  it("bulk delete of owner-filtered rows matched by caller keys", () => {
    expect(one(`const owned = await prisma.file.findMany({ where: { key: { in: parsedInput.keys }, userId: ctx.user.id }, select: { key: true } });\nawait utapi.deleteFiles(owned.map((f) => f.key));`)).toEqual([]);
  });

  // FP: exact equality with a key built from the caller's id leaves only that one key.
  it("exact equality with the caller's server-built key", () => {
    expect(one(`const key = parsedInput.key;\nif (key !== \`avatars/\${ctx.user.id}.png\`) throw new Error("forbidden");\nawait deleteObject(key);`)).toEqual([]);
  });

  // FP: containment is checked on the resolved path inside the caller's own directory, so ../ cannot escape.
  it("path.resolve then containment check in the caller's directory", () => {
    expect(one(`const userDir = path.resolve(UPLOAD_ROOT, session.user.id);\nconst target = path.resolve(userDir, parsedInput.name);\nif (!target.startsWith(userDir + path.sep)) return new Response(null, { status: 400 });\nawait fs.promises.unlink(target);`)).toEqual([]);
  });

  // FP: account deletion wipes the GCS prefix built only from the session id.
  it("GCS deleteFiles by the caller's own prefix", () => {
    expect(one(`const session = await auth();\nif (!session?.user?.id) return new Response(null, { status: 401 });\nawait storage.bucket(BUCKET).deleteFiles({ prefix: \`users/\${session.user.id}/\` });`, "DELETE")).toEqual([]);
  });
});
