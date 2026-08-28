import { describe, expect, it } from "vitest";
import { isCandidate, parseTar } from "./repoArchive";

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
