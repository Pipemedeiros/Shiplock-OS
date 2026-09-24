import { describe, expect, it } from "vitest";
import { findUserControlledDeletes } from "./userControlledKeys";

// Second adversarial round for Step 7F. Each case asserts the correct security
// answer, not the rule's current behaviour, and differs in shape from the
// cases in userControlledKeys.test.ts and userControlledKeys.adversarial.test.ts.
// Synthetic fixtures only.
const one = (body: string, entry = "remove") => findUserControlledDeletes(body, entry);

describe("findUserControlledDeletes round 2: false negatives (real caller-controlled deletions)", () => {
  // FN: useFormState actions receive (prevState, formData) and the FormData parameter is rarely named `formData`.
  it("useFormState action reading a FormData parameter named data", () => {
    expect(one(`"use server";\nexport async function deleteUpload(prev: State, data: FormData) {\n  const key = data.get("key") as string;\n  await deleteObject(key);\n}`, "deleteUpload").length).toBeGreaterThan(0);
  });

  // FN: NextRequest query string is the most common GET/DELETE input and needs no parsing.
  it("req.nextUrl.searchParams.get as the key", () => {
    expect(one(`export async function DELETE(req: NextRequest) {\n  const key = req.nextUrl.searchParams.get("key")!;\n  await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));\n}`, "DELETE").length).toBeGreaterThan(0);
  });

  // FN: Firebase Admin / Google Cloud Storage delete via bucket.file(path).delete().
  it("firebase-admin bucket.file(path).delete()", () => {
    expect(one(`const { path } = await req.json();\nawait getStorage().bucket().file(path).delete();`).length).toBeGreaterThan(0);
  });

  // FN: the Supabase storage bucket handle is stored in a variable before .remove().
  it("supabase storage bucket handle held in a variable", () => {
    expect(one(`const bucket = supabaseAdmin.storage.from("documents");\nawait bucket.remove([parsedInput.path]);`).length).toBeGreaterThan(0);
  });

  // FN: synchronous fs deletion is as destructive as the promise form.
  it("fs.unlinkSync with a form field", () => {
    expect(one(`const name = formData.get("name") as string;\nfs.unlinkSync(path.join(process.cwd(), "public/uploads", name));`).length).toBeGreaterThan(0);
  });

  // FN: the guard is inverted: it returns for the caller's own keys and deletes everyone else's.
  it("inverted ownership guard", () => {
    expect(one(`const key = parsedInput.key;\nif (key.startsWith(\`users/\${ctx.user.id}/\`)) return { ok: true };\nawait deleteObject(key);`).length).toBeGreaterThan(0);
  });

  // FN: ownership is proven for fileId, but the storage key is a separate caller field and is never checked.
  it("owner check on one input field, deletion by a sibling field", () => {
    expect(one(`const { fileId, storageKey } = parsedInput;\nconst file = await prisma.file.findFirst({ where: { id: fileId, userId: ctx.user.id } });\nif (!file) throw new Error("not found");\nawait deleteObject(storageKey);`).length).toBeGreaterThan(0);
  });

  // FN: the prefix check runs on the raw string, then path.join resolves ../ out of the caller's folder.
  it("prefix check defeated by path traversal on the filesystem", () => {
    expect(one(`const { file } = await req.json();\nif (!file.startsWith(\`\${session.user.id}/\`)) return new Response(null, { status: 403 });\nawait fs.promises.unlink(path.join(UPLOAD_ROOT, file));`).length).toBeGreaterThan(0);
  });

  // FN: a service-role Supabase read by a caller-chosen id with no owner filter is an IDOR.
  it("supabaseAdmin row read by caller id with no owner filter", () => {
    expect(one(`const { data: doc } = await supabaseAdmin.from("docs").select("path").eq("id", parsedInput.id).single();\nawait supabaseAdmin.storage.from("docs").remove([doc.path]);`).length).toBeGreaterThan(0);
  });
});

describe("findUserControlledDeletes round 2: false positives (safe code)", () => {
  // FP: Clerk's destructured userId is the caller's real identity; the row's owner is compared to it.
  it("Clerk auth() destructured userId compared to the row owner", () => {
    expect(one(`const { userId } = await auth();\nconst file = await prisma.file.findUnique({ where: { id: parsedInput.id } });\nif (!file || file.ownerId !== userId) return new Response("Forbidden", { status: 403 });\nawait deleteObject(file.key);`)).toEqual([]);
  });

  // FP: Auth.js session read with optional chaining is still the caller's identity.
  it("Auth.js session?.user?.id bound to a variable", () => {
    expect(one(`const session = await auth();\nconst uid = session?.user?.id;\nconst file = await prisma.file.findUnique({ where: { id: parsedInput.id } });\nif (file?.userId !== uid) throw new Error("forbidden");\nawait deleteObject(file.key);`)).toEqual([]);
  });

  // FP: Next.js notFound()/forbidden() throw internally; the guard exits without a throw keyword.
  it("guard that calls notFound()", () => {
    expect(one(`const file = await prisma.file.findUnique({ where: { id: parsedInput.id } });\nif (!file || file.userId !== ctx.user.id) notFound();\nawait deleteObject(file.key);`)).toEqual([]);
  });

  // FP: the deletion sits inside the positive branch of the ownership comparison.
  it("delete inside the then-branch of a positive owner check", () => {
    expect(one(`const file = await prisma.file.findUnique({ where: { id: parsedInput.id } });\nif (file && file.userId === ctx.user.id) {\n  await deleteObject(file.key);\n} else {\n  throw new Error("forbidden");\n}`)).toEqual([]);
  });

  // FP: a module-level Set is an allowlist just like an array literal.
  it("allowlist held in a Set", () => {
    expect(one(`const ALLOWED = new Set(["cache.json", "preview.png"]);\nconst name = parsedInput.name;\nif (!ALLOWED.has(name)) throw new Error("bad name");\nawait fs.promises.unlink(path.join(TMP_DIR, name));`)).toEqual([]);
  });

  // FP: the key must be one of the caller's own keys, fetched with an owner filter.
  it("membership in the caller's own key list", () => {
    expect(one(`const owned = (await prisma.file.findMany({ where: { userId: ctx.user.id }, select: { key: true } })).map((f) => f.key);\nif (!owned.includes(parsedInput.key)) throw new Error("not yours");\nawait deleteObject(parsedInput.key);`)).toEqual([]);
  });

  // FP: a non-exported helper in a cron route file is not browser-callable; its argument comes from the server's own query.
  it("private helper parameter in a cron route file", () => {
    expect(one(`async function purge(keys: string[]) {\n  for (const k of keys) await deleteObject(k);\n}\nexport async function GET() {\n  const stale = await prisma.file.findMany({ where: { expiresAt: { lt: new Date() } } });\n  await purge(stale.map((f) => f.key));\n}`, "GET")).toEqual([]);
  });
});
