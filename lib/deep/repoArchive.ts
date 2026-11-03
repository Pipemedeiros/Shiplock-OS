import { createGunzip } from "node:zlib";
import { Readable } from "node:stream";

/**
 * Whole-repository ingestion, in one request.
 *
 * The previous path read files one at a time through the contents API and was
 * capped at MAX_FILES_PER_REPO = 60 (githubRun.ts). Sixty files is a fraction of
 * a real codebase, so every downstream claim — the route inventory, the import
 * graph, "we read your stack" — was silently bounded by it. Raising that cap in
 * place would mean one HTTP request per file: a 1,500-file repository would
 * spend 1,500 of the installation's 5,000 hourly requests on a single audit.
 *
 * GitHub will hand us the entire tree as a gzipped tar in ONE request, so that
 * is what we do. The tar format is read here directly rather than through a
 * dependency: the ustar header is fixed-width and about eighty lines to parse,
 * and a security product should not add a parser of untrusted archive input it
 * has not read.
 *
 * Budgets are expressed in bytes and files, not in "some number of files that
 * felt safe". A repository that exceeds them is reported as truncated, and the
 * caller writes that into the run's coverage — a thinner audit must never look
 * like a cleaner one.
 */

export interface ArchiveFile {
  path: string;
  content: string;
}

interface ArchiveResult {
  files: ArchiveFile[];
  /** Bytes of source actually read, after filtering. */
  bytesRead: number;
  /** Files skipped because a budget ran out. Zero means the read was complete. */
  skipped: number;
  /** True when any budget was hit. Drives the coverage note on the run. */
  truncated: boolean;
}

/** Text we can reason about. Anything else is not downloaded into memory. */
const CANDIDATE_RE =
  /(^|\/)(\.env(\.[\w-]+)?|package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|tsconfig\.json|next\.config\.[cm]?[jt]s|middleware\.[cm]?[jt]s|.*\.(ts|tsx|js|jsx|mjs|cjs|json|ya?ml|sql|tf|prisma|toml|env)|.*\.pem)$/i;

/** Directories that never contain the customer's own code. */
const IGNORED_RE =
  /(^|\/)(node_modules|\.git|\.next|dist|build|out|coverage|vendor|__pycache__|\.turbo|\.vercel)(\/|$)/;

/** Generated or vendored files that would drown the real source. */
const NOISE_RE = /(^|\/)(.*\.min\.js|.*\.map|.*\.d\.ts|.*\.snap)$/i;

const MAX_TOTAL_BYTES = 24 * 1024 * 1024; // decompressed source we keep
const MAX_FILE_BYTES = 400_000; // one file; larger is generated, not written
// A lockfile is generated too, but it can hold a token in a registry URL, and
// an app's is often over 400 KB (ShipLock's own: 416 KB). Skipped, it made
// every audit partial, so no fixed finding could ever close.
const MAX_LOCKFILE_BYTES = 4_000_000;
const LOCKFILE = /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/;

/** Whether one file is small enough to read; the total budget still applies. */
export function fitsFileBudget(path: string, bytes: number): boolean {
  return bytes <= (LOCKFILE.test(path) ? MAX_LOCKFILE_BYTES : MAX_FILE_BYTES);
}
const MAX_FILES = 4_000;
const MAX_ARCHIVE_BYTES = 120 * 1024 * 1024; // refuse to decompress more than this

/**
 * Strips the leading `owner-repo-sha/` component GitHub puts on every entry.
 * Without this, every path is prefixed with a commit sha and no route matcher
 * anchored on `app/` would ever fire.
 */
function stripRoot(path: string): string {
  const slash = path.indexOf("/");
  return slash === -1 ? path : path.slice(slash + 1);
}

function readOctal(buf: Buffer, offset: number, length: number): number {
  const raw = buf.toString("ascii", offset, offset + length).replace(/\0.*$/, "").trim();
  if (!raw) return 0;
  const value = parseInt(raw, 8);
  return Number.isFinite(value) ? value : 0;
}

/**
 * Parses a ustar archive into entries. Handles the GNU long-name extension
 * ('L'), because repositories with deep paths hit the 100-byte name field and
 * silently losing those files would be the same class of bug as the file cap.
 */
export function parseTar(buf: Buffer, onFile: (path: string, body: Buffer) => boolean | void): void {
  let offset = 0;
  let longName: string | null = null;

  while (offset + 512 <= buf.length) {
    const header = buf.subarray(offset, offset + 512);

    // Two consecutive zero blocks mark the end of the archive.
    if (header.every((b) => b === 0)) break;

    const rawName = header.toString("utf8", 0, 100).replace(/\0.*$/, "");
    const size = readOctal(header, 124, 12);
    const typeFlag = String.fromCharCode(header[156]);
    const prefix = header.toString("utf8", 345, 500).replace(/\0.*$/, "");

    offset += 512;
    const body = buf.subarray(offset, offset + size);
    offset += Math.ceil(size / 512) * 512;

    if (typeFlag === "L") {
      // GNU long name: the next header's real name is this entry's body.
      longName = body.toString("utf8").replace(/\0.*$/, "");
      continue;
    }

    const name = longName ?? (prefix ? `${prefix}/${rawName}` : rawName);
    longName = null;

    // '0' and '\0' are regular files. Directories, symlinks and everything else
    // are skipped: a symlink is a path we would follow out of the archive.
    if (typeFlag !== "0" && typeFlag !== "\0") continue;

    if (onFile(name, body) === false) return;
  }
}

/**
 * The same ustar reader, fed incrementally.
 *
 * `parseTar` needs the whole decompressed archive in memory, which is why a
 * 293MB gzip of corpus-ai could not be read at all: the 120MB ceiling threw
 * rather than truncating, and three of ten preregistered validation
 * repositories produced an exception instead of an audit. A repository we
 * cannot open is the strongest case of "absent is not clean" there is.
 *
 * This keeps the same semantics -- GNU long names, regular files only,
 * symlinks skipped, `false` from the consumer stops the walk -- while holding
 * only the current record. Memory is bounded by the caller's own budgets
 * instead of by the size of the repository.
 */
export function createTarStream(onFile: (path: string, body: Buffer) => boolean | void) {
  let buf: Buffer = Buffer.alloc(0);
  let longName: string | null = null;
  let stopped = false;
  // Bytes of the current record still to be thrown away without buffering, so
  // a 300MB file costs nothing to skip past.
  let discard = 0;

  const padded = (n: number) => Math.ceil(n / 512) * 512;

  const step = (): boolean => {
    if (discard > 0) {
      const take = Math.min(discard, buf.length);
      buf = buf.subarray(take);
      discard -= take;
      return discard === 0 && buf.length > 0;
    }
    if (buf.length < 512) return false;

    const header = buf.subarray(0, 512);
    if (header.every((b) => b === 0)) { stopped = true; return false; }

    const rawName = header.toString("utf8", 0, 100).replace(/\0.*$/, "");
    const size = readOctal(header, 124, 12);
    const typeFlag = String.fromCharCode(header[156]);
    const prefix = header.toString("utf8", 345, 500).replace(/\0.*$/, "");
    const total = padded(size);

    // The body has to be present in full before the record can be handed over.
    if (buf.length < 512 + total) {
      // A record we are going to skip anyway can start discarding immediately.
      const name = longName ?? (prefix ? `${prefix}/${rawName}` : rawName);
      if (typeFlag !== "0" && typeFlag !== "\0" && typeFlag !== "L") {
        buf = buf.subarray(512);
        discard = total;
        longName = null;
        return true;
      }
      void name;
      return false;
    }

    const body = buf.subarray(512, 512 + size);
    buf = buf.subarray(512 + total);

    if (typeFlag === "L") { longName = body.toString("utf8").replace(/\0.*$/, ""); return true; }
    const name = longName ?? (prefix ? `${prefix}/${rawName}` : rawName);
    longName = null;
    if (typeFlag !== "0" && typeFlag !== "\0") return true;
    if (onFile(name, body) === false) { stopped = true; return false; }
    return true;
  };

  return {
    push(chunk: Buffer): boolean {
      if (stopped) return false;
      buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
      while (!stopped && step()) { /* consume as many records as the buffer holds */ }
      return !stopped;
    },
    end(): void { while (!stopped && step()) { /* drain */ } },
    get stopped() { return stopped; },
  };
}

/** True for a path worth reading. Exported so the ingestion rules are testable. */
export function isCandidate(path: string): boolean {
  if (IGNORED_RE.test(path)) return false;
  if (NOISE_RE.test(path)) return false;
  return CANDIDATE_RE.test(path);
}

/**
 * Downloads and reads a repository at `ref`.
 *
 * Throws on a transport failure rather than returning an empty result: an empty
 * file list read as "nothing to see" would let a failed download present as a
 * clean audit, which is the exact failure mode this codebase has shipped before.
 */
export async function fetchRepoArchive(
  token: string,
  fullName: string,
  ref = "HEAD",
  timeoutMs = 60_000,
): Promise<ArchiveResult> {
  const res = await fetch(`https://api.github.com/repos/${fullName}/tarball/${ref}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "ShipLock",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (!res.ok) throw new Error(`GitHub tarball HTTP ${res.status} for ${fullName}`);
  if (!res.body) throw new Error(`GitHub tarball for ${fullName} returned no body`);

  const files: ArchiveFile[] = [];
  let bytesRead = 0;
  let skipped = 0;
  let truncated = false;
  let inflated = 0;

  // STREAMED, NOT BUFFERED. This used to read the whole gzip into memory,
  // refuse anything over MAX_ARCHIVE_BYTES, and then decompress the lot with
  // the same number as an output cap -- so a large monorepo threw instead of
  // being audited. Measured 2026-09-06: three of ten preregistered validation
  // repositories (corpus-af 163MB, corpus-an 139MB, corpus-ai 293MB gzipped) produced
  // an exception rather than a report, which is the "absent is not clean"
  // failure at its worst -- a repository we could not open said nothing at all.
  //
  // Now the archive is decompressed and parsed a chunk at a time, only files
  // that pass the budgets are retained, and everything else is discarded
  // without being held. MAX_ARCHIVE_BYTES becomes a bound on how much we will
  // decompress before stopping, so runtime stays inside the function's ceiling
  // and the result is a truncated audit that SAYS it is truncated.
  const parser = createTarStream((rawPath, body) => {
    const path = stripRoot(rawPath);
    if (!path || !isCandidate(path)) return;
    if (!fitsFileBudget(path, body.length)) { skipped++; return; }
    if (files.length >= MAX_FILES || bytesRead + body.length > MAX_TOTAL_BYTES) {
      skipped++;
      truncated = true;
      return;
    }
    files.push({ path, content: body.toString("utf8") });
    bytesRead += body.length;
  });

  const gunzip = createGunzip();
  const source = Readable.fromWeb(res.body as Parameters<typeof Readable.fromWeb>[0]);

  await new Promise<void>((resolve, reject) => {
    const finish = () => resolve();
    gunzip.on("data", (chunk: Buffer) => {
      inflated += chunk.length;
      if (inflated > MAX_ARCHIVE_BYTES) {
        // Past the decompression budget. Everything after this is unread, and
        // the caller reports that as coverage rather than as success.
        truncated = true;
        source.destroy();
        gunzip.destroy();
        finish();
        return;
      }
      if (!parser.push(chunk)) { source.destroy(); gunzip.destroy(); finish(); }
    });
    gunzip.on("end", () => { parser.end(); finish(); });
    gunzip.on("close", finish);
    gunzip.on("error", (err: NodeJS.ErrnoException) => {
      // A stream torn down on purpose is not a failure.
      if (err?.code === "ERR_STREAM_PREMATURE_CLOSE") return finish();
      reject(err);
    });
    source.on("error", reject);
    source.pipe(gunzip);
  });

  return { files, bytesRead, skipped, truncated };
}
