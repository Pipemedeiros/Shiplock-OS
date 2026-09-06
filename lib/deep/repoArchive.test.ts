import { describe, expect, it } from "vitest";
import { isCandidate, parseTar, createTarStream } from "./repoArchive";

/** Builds a ustar entry so the parser is tested against real bytes, not a mock. */
function entry(name: string, body: string, typeFlag = "0"): Buffer {
  const header = Buffer.alloc(512);
  header.write(name.slice(0, 100), 0, "utf8");
  header.write("000644 \0", 100, "ascii");
  header.write(body.length.toString(8).padStart(11, "0") + " ", 124, "ascii");
  header.write(typeFlag, 156, "ascii");
  header.write("ustar\0" + "00", 257, "ascii");
  // Checksum is not verified by the parser, so it is left zeroed deliberately.
  const content = Buffer.alloc(Math.ceil(body.length / 512) * 512);
  content.write(body, 0, "utf8");
  return Buffer.concat([header, content]);
}

describe("parseTar", () => {
  it("reads regular files and stops at the end-of-archive blocks", () => {
    const tar = Buffer.concat([
      entry("repo-abc123/app/api/x/route.ts", "export async function GET() {}"),
      entry("repo-abc123/package.json", '{"name":"x"}'),
      Buffer.alloc(1024),
    ]);

    const seen: string[] = [];
    parseTar(tar, (p) => { seen.push(p); });
    expect(seen).toEqual(["repo-abc123/app/api/x/route.ts", "repo-abc123/package.json"]);
  });

  it("skips directories and symlinks", () => {
    // A symlink is a path that points out of the archive. Following one is how
    // an archive reader becomes a file-disclosure bug.
    const tar = Buffer.concat([
      entry("repo/dir", "", "5"),
      entry("repo/link", "../../etc/passwd", "2"),
      entry("repo/real.ts", "const a = 1;"),
      Buffer.alloc(1024),
    ]);

    const seen: string[] = [];
    parseTar(tar, (p) => { seen.push(p); });
    expect(seen).toEqual(["repo/real.ts"]);
  });

  it("honours the GNU long-name extension", () => {
    // Deep paths exceed the 100-byte name field. Dropping them would be the
    // same silent-incompleteness bug as the old sixty-file cap.
    const longPath = "repo/" + "nested/".repeat(20) + "route.ts";
    const tar = Buffer.concat([
      entry("././@LongLink", longPath, "L"),
      entry(longPath.slice(0, 100), "export const GET = 1;"),
      Buffer.alloc(1024),
    ]);

    const seen: string[] = [];
    parseTar(tar, (p) => { seen.push(p); });
    expect(seen).toEqual([longPath]);
  });
});

describe("isCandidate", () => {
  it("accepts application source and manifests", () => {
    for (const p of ["app/api/x/route.ts", "lib/db.ts", "package.json", "schema.prisma", "infra/main.tf", ".env.example"]) {
      expect(isCandidate(p), p).toBe(true);
    }
  });

  it("refuses dependency and build directories", () => {
    for (const p of ["node_modules/react/index.js", ".next/server/app.js", "dist/bundle.js", "coverage/lcov.info"]) {
      expect(isCandidate(p), p).toBe(false);
    }
  });

  it("refuses generated files that would drown the real source", () => {
    for (const p of ["public/app.min.js", "app/page.js.map", "types/index.d.ts"]) {
      expect(isCandidate(p), p).toBe(false);
    }
  });

  it("refuses binaries outright", () => {
    for (const p of ["assets/logo.png", "docs/spec.pdf", "bin/tool"]) {
      expect(isCandidate(p), p).toBe(false);
    }
  });
});

// BLOCKER 3 (2026-09-06). Three of ten preregistered validation repositories
// could not be ingested at all: corpus-af 163MB, corpus-an 139MB and corpus-ai 293MB
// gzipped, against a 120MB ceiling that threw. A repository we cannot open
// produced an exception, and "absent is not clean" applies hardest there.
//
// The fix is to stream: decompress and parse incrementally, keep only files
// that pass the budgets, and discard the rest without ever holding the whole
// archive. Memory is then bounded by the 24MB source budget rather than by the
// repository's size.
describe("streaming tar parse", () => {
  // A minimal ustar archive, built here so the test owns its input.
  const rec = (name: string, body: string) => {
    const h = Buffer.alloc(512);
    h.write(name, 0, 100, "utf8");
    h.write("0000644\0", 100, 8, "ascii");
    h.write(body.length.toString(8).padStart(11, "0") + "\0", 124, 12, "ascii");
    h.write("0", 156, 1, "ascii");
    h.write("ustar\0" + "00", 257, 8, "ascii");
    h.fill(" ", 148, 156);
    let sum = 0; for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8, "ascii");
    const pad = Buffer.alloc(Math.ceil(body.length / 512) * 512);
    pad.write(body, 0, "utf8");
    return Buffer.concat([h, pad]);
  };
  const archive = Buffer.concat([
    rec("repo-sha/a.ts", "export const a = 1;"),
    rec("repo-sha/big.ts", "x".repeat(1200)),
    rec("repo-sha/b.ts", "export const b = 2;"),
    Buffer.alloc(1024),
  ]);

  it("reads the same files as the buffered parser, however the chunks fall", () => {
    const buffered: string[] = [];
    parseTar(archive, (p) => { buffered.push(p); });
    for (const size of [1, 7, 512, 513, 1024, 100000]) {
      const streamed: string[] = [];
      const s = createTarStream((p) => { streamed.push(p); });
      for (let i = 0; i < archive.length; i += size) s.push(archive.subarray(i, i + size));
      s.end();
      expect(streamed, `chunk size ${size}`).toEqual(buffered);
    }
  });

  it("hands back the body intact across a chunk boundary", () => {
    const seen: Record<string, string> = {};
    const s = createTarStream((p, b) => { seen[p] = b.toString("utf8"); });
    for (let i = 0; i < archive.length; i += 3) s.push(archive.subarray(i, i + 3));
    s.end();
    expect(seen["repo-sha/a.ts"]).toBe("export const a = 1;");
    expect(seen["repo-sha/big.ts"]).toBe("x".repeat(1200));
  });

  it("stops when the consumer says stop", () => {
    const seen: string[] = [];
    const s = createTarStream((p) => { seen.push(p); return false; });
    for (let i = 0; i < archive.length; i += 64) s.push(archive.subarray(i, i + 64));
    s.end();
    expect(seen).toEqual(["repo-sha/a.ts"]);
  });
});
