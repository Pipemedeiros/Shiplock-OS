import type { Severity } from "@/lib/types";
import { createPrivateKey, createPublicKey } from "node:crypto";

// PURE GitHub source-scan detectors — no network. All I/O (repo reads, OSV
// lookups) lives in lib/deep/github.ts; this module turns fetched content into
// deep_findings-shaped findings and is fully unit-testable with fixtures. Same
// stable-id + severity contract as lib/deep/envaudit.ts.

export interface GithubFinding {
  id: string; // stable diff key
  severity: Severity;
  title: string;
  consequence: string;
  packageName: string | null;
  version: string | null;
  vulnId: string | null;
  cveId: string | null;
}

export interface RepoFile {
  path: string;
  content: string;
}

export interface Dep {
  name: string;
  version: string;
}

// ── Committed secrets ──────────────────────────────────────────────────────
// Deliberately high-precision patterns (real leaked-credential shapes), so we
// report credential values rather than guessing from variable names.
const SECRET_PATTERNS: { id: string; label: string; re: RegExp }[] = [
  { id: "private_key", label: "a PEM private key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { id: "supabase_service_key", label: "a Supabase service-role key", re: /\bsb_secret_[A-Za-z0-9_-]{10,}/ },
  { id: "aws_access_key", label: "an AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/ },
  // The shape proves the format, not the vendor: compatible providers
  // (Moonshot, DeepSeek and others) issue the same sk- keys (release run r6).
  { id: "openai_key", label: "an API key in OpenAI's format", re: /\bsk-[A-Za-z0-9]{20,}\b/ },
];

// OpenSSH uses its own binary container, which Node's PEM parser does not
// accept. Read the bounded envelope rather than treating its header as a key.
function hasOpenSshKeyMaterial(body: string): boolean {
  try {
    const data = Buffer.from(body, "base64");
    const magic = Buffer.from("openssh-key-v1\0");
    if (!data.subarray(0, magic.length).equals(magic)) return false;
    let offset = magic.length;
    const uint = () => { const n = data.readUInt32BE(offset); offset += 4; return n; };
    const field = () => {
      const length = uint();
      if (length > data.length - offset) throw new Error("truncated key");
      const value = data.subarray(offset, offset + length); offset += length; return value;
    };
    const cipher = field().toString();
    const kdf = field().toString();
    const options = field();
    if (uint() !== 1) return false;
    const publicKey = field();
    const privateKey = field();
    if (offset !== data.length || publicKey.length < 32 || privateKey.length < 64) return false;
    const reader = (buffer: Buffer) => {
      let cursor = 0;
      return {
        field() {
          const length = buffer.readUInt32BE(cursor); cursor += 4;
          if (length > buffer.length - cursor) throw new Error("truncated field");
          const value = buffer.subarray(cursor, cursor + length); cursor += length; return value;
        },
        rest: () => buffer.subarray(cursor),
      };
    };
    const pub = reader(publicKey);
    const algorithm = pub.field().toString();
    if (!/^(?:ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp(?:256|384|521))$/.test(algorithm)) return false;
    if (cipher !== "none") return /^(?:aes(?:128|192|256)-(?:ctr|cbc|gcm@openssh.com)|chacha20-poly1305@openssh.com)$/.test(cipher) && kdf === "bcrypt" && options.length >= 20;
    if (kdf !== "none" || options.length !== 0 || privateKey.readUInt32BE(0) !== privateKey.readUInt32BE(4)) return false;
    const priv = reader(privateKey.subarray(8));
    if (priv.field().toString() !== algorithm) return false;
    const equalField = (minimum: number) => {
      const field = priv.field();
      return field.length >= minimum && field.equals(pub.field());
    };
    if (algorithm === "ssh-ed25519") {
      const publicBytes = priv.field();
      const secret = priv.field();
      if (publicBytes.length !== 32 || !publicBytes.equals(pub.field()) || secret.length !== 64 || !secret.subarray(32).equals(publicBytes)) return false;
      const key = createPrivateKey({ key: { kty: "OKP", crv: "Ed25519", d: secret.subarray(0, 32).toString("base64url"), x: publicBytes.toString("base64url") }, format: "jwk" });
      if (createPublicKey(key).export({ format: "jwk" }).x !== publicBytes.toString("base64url")) return false;
    } else if (algorithm === "ssh-rsa") {
      // Public format is e,n; private format is n,e,d,iqmp,p,q.
      const e = pub.field(); const n = pub.field();
      if (n.length < 64 || e.length === 0 || !priv.field().equals(n) || !priv.field().equals(e)) return false;
      for (let i = 0; i < 4; i++) if (priv.field().length < 16) return false;
    } else if (algorithm === "ssh-dss") {
      for (let i = 0; i < 4; i++) if (!equalField(16)) return false;
      if (priv.field().length < 16) return false;
    } else {
      if (!equalField(8) || !equalField(65) || priv.field().length < 32) return false;
    }
    if (pub.rest().length !== 0) return false;
    priv.field(); // comment
    const padding = priv.rest();
    return padding.length <= 8 && padding.every((value, index) => value === index + 1);

  } catch {
    return false;
  }
}

/** Whether the content holds a PEM private key that actually parses, so a
 * truncated or example block is not reported as a key. */
export function hasParseablePrivateKey(content: string): boolean {
  // PEM values are commonly JSON-escaped or pasted in line/block comments.
  // Decode line separators only, without evaluating customer source.
  const normalized = content.replace(/\\r\\n|\\n|\\r/g, "\n");
  const blocks = normalized.matchAll(/-----BEGIN ((?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY)-----([\s\S]*?)-----END \1-----/g);
  for (const [, label, rawBody] of blocks) {
    // Try the untouched PEM first: base64 can legitimately begin with //,
    // which comment cleanup would otherwise remove and corrupt the key.
    try {
      createPrivateKey(`-----BEGIN ${label}-----${rawBody}-----END ${label}-----`);
      return true;
    } catch {
      // Wrapped/commented PEM still uses the normalization below.
    }
    const cleanBody = rawBody.replace(/^\s*(?:\/\/|\*|#) ?/gm, "").trim();
    // Traditional PEM encryption leaves this envelope visible; the private
    // parameters cannot be parsed without the passphrase. Require the known
    // cipher metadata, correct IV size and a substantial aligned ciphertext.
    const encrypted = /^Proc-Type: 4,ENCRYPTED\r?\nDEK-Info: (AES-(?:128|192|256)-CBC|DES-EDE3-CBC|DES-CBC),([A-Fa-f0-9]+)\r?\n\s*([A-Za-z0-9+/=\s]+)$/.exec(cleanBody);
    if (encrypted && /^(?:RSA|EC|DSA) PRIVATE KEY$/.test(label)) {
      const blockSize = encrypted[1].startsWith("AES") ? 16 : 8;
      const ciphertext = encrypted[3].replace(/\s/g, "");
      const bytes = Buffer.from(ciphertext, "base64");
      if (encrypted[2].length === blockSize * 2 && /^[A-Za-z0-9+/]+={0,2}$/.test(ciphertext) &&
          bytes.length >= (label.startsWith("EC") ? 64 : 128) && bytes.length % blockSize === 0) return true;
    }
    const body = cleanBody.replace(/\s/g, "");
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body)) continue;
    if (label === "OPENSSH PRIVATE KEY" && hasOpenSshKeyMaterial(body)) return true;
    try {
      createPrivateKey(`-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`);
      return true;
    } catch {
      // A header, a truncated fixture or arbitrary base64 is not a key.
    }
  }
  return false;
}

// A committed dotenv file.
const COMMITTED_ENV_RE = /(^|\/)\.env(\.[A-Za-z0-9_-]+)*$/;

// ...except the ones every project is SUPPOSED to commit.
//
// `.env.example` and `.env.template` are the documented way to tell a new
// contributor which variables exist. Auditing a real Supabase starter reported
// its committed `.env.template` as a CRITICAL leak, which is both wrong and the
// most common file shape in this market: our own repository never caught it
// because it gitignores `.env*`, so the placeholder is never committed here.
//
// Their CONTENT is still scanned by the credential patterns below, so a real key
// pasted into `.env.example` is still reported. It is the file's existence that
// stops being a finding.
// Release run r2 (2026-10-12): templates are also named in other languages
// (.env.exemple, .env.ejemplo, .env.beispiel) and in the plural.
const ENV_PLACEHOLDER_RE = /\.(examples?|exemple|ejemplo|esempio|beispiel|template|sample|dist|defaults?|placeholder|tpl)$/i;

/** Prefixes whose values are published to the browser on purpose. */
const PUBLIC_ENV_PREFIX = /^(NEXT_PUBLIC_|EXPO_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|GATSBY_)/;

/** A filled-in value rather than a fill-me-in marker. */
const ENV_FILLED_VALUE = /^["']?(?!\s*$)(?!your[-_])(?!<)(?!\.\.\.)(?!xxx)[^\s"']{16,}/i;

/**
 * Values that are long enough to look filled in but carry no secret.
 *
 * A DATABASE_URL pointing at localhost is the default every starter ships with,
 * and a pk_test_ / pk_live_ publishable key is published on purpose. Auditing a
 * 7,000-star boilerplate reported its committed .env as a credential leak on the
 * strength of `postgresql://postgres@localhost:5432/db`.
 */
const HARMLESS_ENV_VALUE =
  /^["']?file:|^["']?(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|http|https):\/\/[^\s"']*(?:localhost|127\.0\.0\.1|0\.0\.0\.0|@db[:\/]|@postgres[:\/]|@mysql[:\/]|host\.docker\.internal)/i;

/**
 * Keys whose NAME says they carry a credential.
 *
 * Without this, any long value counted. A 7,000-star boilerplate's committed
 * .env.production was reported CRITICAL because it sets CHECKLY_PROJECT_NAME
 * and a contact email address, neither of which is a secret by any reading.
 */
const CREDENTIAL_KEY_RE =
  /(SECRET|PASSWORD|PRIVATE_KEY|API_?KEY|_KEY$|TOKEN|CREDENTIAL|SERVICE_ROLE|DSN|CONNECTION_STRING|DATABASE_URL|AUTH)/i;

/** Vendor prefixes that mark a key as publishable. */
const PUBLISHABLE_KEY_VALUE = /^["']?(?:pk_(?:test|live)_|sb_publishable_|whsec_test_)/i;

/**
 * Whether a committed env file actually carries a secret.
 *
 * A file holding only NEXT_PUBLIC_/EXPO_PUBLIC_ values carries nothing private:
 * those ship to the browser by design, and the Supabase anon key is meant to be
 * there. A real Supabase starter committed exactly that and was reported as a
 * CRITICAL credential leak, which is the same overreach as flagging the
 * publishable key in a bundle, something this codebase already refuses to do.
 */
/**
 * A value that restates its own key in shouty snake case -- SOME_CLOUDFLARE_TOKEN,
 * CHANGE_ME_PLEASE. Nobody's real credential is spelled this way.
 */
// At least one underscore: an uppercase hex key (F0E5AD93...) is a value.
const ENV_PLACEHOLDER_VALUE = /^["']?(?=[A-Z0-9_]{6,}["']?$)[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+["']?$/;
/** The textbook template URL: user:password@host (release run r2, 2026-10-12). */
const PLACEHOLDER_URL_RE = /:\/\/(user(name)?|admin|postgres|root):(password|pass|secret|changeme)@(host(name)?|server)(?=[:/"'?\s]|$)/i;
/** A URL with `user:pass@` in it. That is a credential, wherever it points. */
const ENV_URL_WITH_CREDENTIALS = /^["']?[a-z+]+:\/\/[^\s"'@/]*:[^\s"'@/]+@/i;
/** A plain URL carrying no inline credentials is an endpoint, not a secret. */
const ENV_URL_VALUE = /^["']?https?:\/\/(?![^\s"'@]*:[^\s"'@]*@)[^\s"']*["']?$/i;

/** The values of a committed env file that read as filled-in secrets. */
function envSecretValues(content: string): string[] {
  const values: string[] = [];
  for (const line of content.split("\n")) {
    const match = /^\s*([A-Za-z0-9_]+)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    const [, key, rawValue] = match;
    if (PUBLIC_ENV_PREFIX.test(key)) continue;
    if (!CREDENTIAL_KEY_RE.test(key)) continue;
    const value = rawValue.trim();
    if (HARMLESS_ENV_VALUE.test(value) || PUBLISHABLE_KEY_VALUE.test(value)) continue;
    // A URL carrying inline credentials is a secret whatever else the line
    // says. This is checked FIRST because the host is so often example.com,
    // and `looksSynthetic` reads that as a placeholder -- which would have
    // dropped `postgresql://admin:Hunter2Hunter2@db.prod.example.com`, a real
    // production connection string. Caught by the pre-existing test.
    if (ENV_URL_WITH_CREDENTIALS.test(value)) { if (!PLACEHOLDER_URL_RE.test(value)) values.push(value); continue; }
    // A password HASH is not a password. bcrypt, argon2, scrypt and pbkdf2
    // digests are what a codebase is supposed to store, and corpus-ag's committed
    // dev env carries one.
    if (/^["']?\$(?:2[aby]?|argon2(?:id|i|d)|scrypt|pbkdf2)\$/.test(value)) continue;
    // The project's stated rule is that the VALUE decides whether we speak at
    // all, and the placeholder test it already owns was never applied here.
    // Applied to the value alone, never the whole line, for the same reason.
    if (looksSynthetic(value, value)) continue;
    // A shouty-snake placeholder restating its key, and a bare URL with no
    // credentials in it, are not secrets either.
    if (ENV_PLACEHOLDER_VALUE.test(value) || ENV_URL_VALUE.test(value)) continue;
    // A bare hostname is configuration, whatever its key says: attempt 6 called
    // FIREBASE_AUTH_DOMAIN (acme-app.firebaseapp.com) a random credential.
    // DNS labels are at most 63 characters, so a JWT's segments never match.
    if (/^["']?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+["']?$/i.test(value) && /\.[a-z]{2,}["']?$/i.test(value)) continue;
    if (ENV_FILLED_VALUE.test(value)) values.push(value);
  }
  return values;
}

const VENDOR_NAMES: [RegExp, string][] = [
  [/^["']?sk_live_/, "a Stripe live secret key"], [/^["']?rk_live_/, "a Stripe live restricted key"],
  [/^["']?sb_secret_/, "a Supabase secret key"], [/^["']?sk-ant-/, "an Anthropic API key"],
  [/^["']?sk-(proj-)?[A-Za-z0-9_-]{20,}/, "an API key in OpenAI's format"], [/^["']?AKIA[0-9A-Z]{16}/, "an AWS access key id"],
  [/^["']?(gh[pousr]_|github_pat_)/, "a GitHub token"], [/^["']?xox[abprs]-/, "a Slack token"],
  [/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, "a private key"],
];

/** Shannon bits per character. */
function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const c of value) counts.set(c, (counts.get(c) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) bits -= (n / value.length) * Math.log2(n / value.length);
  return bits;
}

/**
 * What each credential in a committed env file holds, by kind and never by
 * value: an engineer or a labeler can challenge the finding without
 * opening the file. Hosts are named only as local, a template's, or remote.
 */
export function envValueShapes(content: string): { name: string; shape: string }[] {
  const secret = new Set(envSecretValues(content));
  const shapes: { name: string; shape: string }[] = [];
  for (const line of content.split("\n")) {
    const match = /^\s*([A-Za-z0-9_]+)\s*=\s*(.*)$/.exec(line);
    if (!match || !secret.has(match[2].trim())) continue;
    const value = match[2].trim();
    const bare = value.replace(/^["']|["']$/g, "");
    const vendor = VENDOR_NAMES.find(([re]) => re.test(value))?.[1];
    const shape = ENV_URL_WITH_CREDENTIALS.test(value)
      ? `a connection URL with a password, to ${PLACEHOLDER_HOST_RE.test(value) ? "a template's host" : LOCAL_HOST_RE.test(value) ? "a local host" : "a remote host"}`
      : vendor ?? `${bare.length} ${entropy(bare) >= 3.5 ? "random-looking " : ""}characters`;
    shapes.push({ name: match[1], shape });
  }
  return shapes;
}

/** The shapes as a sentence for a finding, capped so a long file stays readable. */
function describeShapes(content: string): string {
  const shapes = envValueShapes(content);
  if (shapes.length === 0) return "";
  const listed = shapes.slice(0, 4).map((s) => `${s.name} (${s.shape})`).join(", ");
  const rest = shapes.length - 4;
  // Attempt 6: "and 2 more" read as the file's total; say what is counted.
  const entries = content.split("\n").filter((line) => /^\s*[A-Za-z0-9_]+\s*=/.test(line)).length;
  return ` Its credentials, described without their values: ${listed}${rest > 0 ? `, and ${rest} other credential${rest === 1 ? "" : "s"}` : ""}. The file has ${entries} entries in all.`;
}

function envFileHasSecret(content: string): boolean {
  return envSecretValues(content).length > 0;
}

// Census 2026-10-06 (withheld census shown-without-agent-2026-10-06): 8
// of 9 committed-env criticals held no live credential: a generator
// template's SQLite path and local emulator defaults. CRITICAL now needs a
// value shaped like a live credential. A filled value we cannot judge stays a
// WARNING that says so: the trade is a missed escalation, never a missed
// finding.
/** Vendor formats that are a credential wherever they appear. */
const VENDOR_SECRET_RE =
  /\bsb_secret_[A-Za-z0-9_-]{10,}|\b[sr]k_live_[A-Za-z0-9]{16,}|\bsk-ant-[A-Za-z0-9_-]{20,}|\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{30,}|\bxox[abprs]-[A-Za-z0-9-]{10,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/;
/** Files named for a deployed environment rather than local development. */
const DEPLOYED_ENV_NAME_RE = /(^|\/)\.env(\.(production|prod|staging|stage|live|save|bak|backup|old|orig|copy))?$/i;
const LOCAL_HOST_RE = /localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal/i;

/** Whether a committed env file holds a value shaped like a live credential. */
/** A template's host: db.your-project.supabase.co, [region], <host>, example. */
const PLACEHOLDER_HOST_RE = /@[^\s"'/]*(your[-_]|\[|<|example|xxx|changeme)/i;

function envFileHasLiveCredential(path: string, content: string): boolean {
  const values = envSecretValues(content);
  // An inline-credential URL that survived the harmless-host filter points
  // at a real host, unless the host is a template's placeholder (CORPUS-6).
  if (values.some((v) => ENV_URL_WITH_CREDENTIALS.test(v) && !PLACEHOLDER_HOST_RE.test(v))) return true;
  if (values.some((v) => VENDOR_SECRET_RE.test(v))) return true;
  return values.length > 0 && DEPLOYED_ENV_NAME_RE.test(path) && !LOCAL_HOST_RE.test(content);
}

// ── Fixtures are not leaks ─────────────────────────────────────────────────
// A test suite that exercises a secret detector has to contain things shaped
// like secrets. Reporting those is how an audit produces fifteen criticals
// about a repository with nothing wrong with it, and one wrong critical costs
// more trust than five right ones earn.
//
// The rule is NOT "skip test files". Real credentials are committed in test
// files all the time -- a suite that talks to a live sandbox needs a real key.
// So the path decides how loudly we speak, and the VALUE decides whether we
// speak at all.
// Seed and fixture scripts populate a development database. Their passwords are
// dev logins by construction: a 7,000-star starter kit sets ADMIN_PASSWORD to
// 'admin@123' in prisma/seed.ts, and telling its author to rotate that is noise.
const SEED_PATH_RE = /(^|\/)(seeds?|fixtures?)\.[cm]?[jt]s$|(^|\/)(seeds?|fixtures?)\//i;

// The directory list is not decoration: `playwright/`, `e2e/` and `cypress/`
// are where a real codebase keeps the suite that signs in as a fake user, and
// omitting them reported corpus-a's Playwright signup password and corpus-c'
// MOCK_PASSWORD as committed credentials, at CRITICAL, on a stranger's repo.
// The file list covers the setup module every framework wants at the root --
// vitestSetup.ts has no dot before "Setup", so a pattern written for
// jest.setup.ts matched neither it nor setupTests.ts.
// `integration-tests/` and `e2e-tests/` are test directories that this pattern
// missed, because the segment had to BE `tests` rather than end in it. Seven
// injection criticals across the 2026-09-06 validation sat in exactly that
// shape. A `<word>-tests` segment is the same directory by another name.
const TEST_PATH_RE =
  /(^|\/)(__tests__|__mocks__|__fixtures__|[\w.-]*[-.]tests?|tests?|spec|fixtures|mocks|examples?|playwright|e2e|cypress|testing)(\/)|\.(test|spec|e2e)\.[cm]?[jt]sx?$|\.fixture\.[cm]?[jt]sx?$|(^|\/)(vitest|jest|playwright|cypress)\.config\.[cm]?[jt]s$|(^|\/)(jest\.setup|vitestSetup|setupTests|test-setup|testSetup)\.[cm]?[jt]sx?$/i;

/**
 * CI, build and container configuration -- scaffolding that does not ship.
 *
 * Separate from isTestPath because it is a different argument: these files are
 * not a test suite, but they are the documented home of a build-time stand-in,
 * and the values in them are read by a pipeline rather than served to a user.
 */
export function isScaffoldPath(path: string): boolean {
  return /(^|\/)(\.github|\.gitlab|\.circleci|\.buildkite)\//i.test(path)
    || /(^|\/)(docker-compose[\w.-]*\.ya?ml|Dockerfile[\w.-]*|devcontainer\.json)$/i.test(path)
    || /(^|\/)(skaffold|docker-bake)\.[\w.]*ya?ml$/i.test(path)
    // A repository's own scripts/ directory is the same argument as .github/:
    // build, release and local-setup code run by a pipeline or a maintainer,
    // never served to a user. Deliberately NOT migrations/ -- those run in
    // production against the real database, so they stay loud.
    || /(^|\/)scripts?\//i.test(path);
}

/** Whether this file is test scaffolding rather than shipped code. */
export function isTestPath(path: string): boolean {
  return TEST_PATH_RE.test(path) || SEED_PATH_RE.test(path);
}

// Values that announce themselves as fake. Vendors publish several of these
// verbatim in their own documentation -- AKIAIOSFODNN7EXAMPLE is Amazon's.
// Matched as substrings, not words: the marker is usually welded into the
// value itself. AKIAIOSFODNN7EXAMPLE and sb_secret_example_key both contain
// "example" with no word boundary anywhere near it, and a \b here silently
// matched neither -- which is the whole false-positive burst all over again.
const SYNTHETIC_RE =
  /(example|fake|dummy|placeholder|redacted|notreal|test[-_]?key|testkey|testing|mock|stub|sample|your[-_]\w+|changeme|xxxx|aaaa|00000|1234567|deadbeef|foobar|lorem)/i;

/**
 * Whether a matched credential looks manufactured for a test.
 *
 * Deliberately conservative: it judges the matched text and its immediate line,
 * not the file. A genuine key that happens to sit near the word "example" is
 * rare; a fixture that contains none of these markers still gets reported, just
 * more quietly.
 */
export function looksSynthetic(match: string, line: string): boolean {
  if (SYNTHETIC_RE.test(match) || SYNTHETIC_RE.test(line)) return true;
  // A `test-` or `test_` segment anywhere in the value: "test-service-role-key".
  if (/(^|["'`\s=:(,\-_])test[-_]/i.test(match) || /(^|["'`\s=:(,])test[-_]/i.test(line)) return true;
  // Nobody's real key spells the alphabet. abcdefgh and AbCdEfGh are the two
  // ways a person types a placeholder they do not want to think about.
  if (hasAlphabeticRun(match) || hasAlphabeticRun(line)) return true;
  // A PEM header with nothing under it, or a key body of one repeated
  // character, is a shape and not a key.
  if (/-----BEGIN/.test(match) && /-----BEGIN[^]{0,40}(-----END|["'`])/.test(line)) return true;
  // A PEM whose base64 body is too short to BE a key. A real RSA or EC private
  // key runs to hundreds of base64 characters; outline's committed .env.test
  // carries a header, sixteen characters, and a footer, and that was reported
  // as a leaked private key at CRITICAL.
  const pem = /-----BEGIN[^-]*-----([\s\S]*?)-----END/.exec(line) ?? /-----BEGIN[^-]*-----([\s\S]*?)-----END/.exec(match);
  if (pem && pem[1].replace(/[^A-Za-z0-9+/=]/g, "").length < 100) return true;
  const body = match.replace(/[^A-Za-z0-9]/g, "");
  if (body.length >= 8 && new Set(body.toLowerCase()).size <= 3) return true;
  return false;
}

/**
 * Whether a vendor-shaped match is only its prefix and one repeated character
 * (E5: AKIA then sixteen X's in a docs sample). Issued keys are random, so a
 * filler body is a shape on any path, not a credential; unlike the markers in
 * looksSynthetic, this one holds in shipped code too.
 */
function isFillerKey(match: string): boolean {
  const body = match.replace(/^(AKIA|sb_secret_|sk-)/, "").replace(/[^A-Za-z0-9]/g, "");
  return body.length >= 8 && new Set(body.toLowerCase()).size === 1;
}

/** Six or more consecutive letters in alphabetical order — abcdef, AbCdEf. */
function hasAlphabeticRun(text: string): boolean {
  const letters = text.toLowerCase().replace(/[^a-z]/g, "");
  let run = 1;
  for (let i = 1; i < letters.length; i++) {
    run = letters.charCodeAt(i) === letters.charCodeAt(i - 1) + 1 ? run + 1 : 1;
    if (run >= 6) return true;
  }
  return false;
}

/** Whether the match sits on a comment line. */
export function isCommentLine(line: string): boolean {
  return /^\s*(\/\/|\*|\/\*|#|--)/.test(line);
}

/** The line a match sits on, for judging it in context. */
function lineOf(content: string, index: number): string {
  const start = content.lastIndexOf("\n", index) + 1;
  const end = content.indexOf("\n", index);
  return content.slice(start, end === -1 ? undefined : end);
}

/** Committed credentials in the repository: env files with values, private keys
 * and known token formats. */
export function scanSecrets(files: RepoFile[]): GithubFinding[] {
  const findings: GithubFinding[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    if (COMMITTED_ENV_RE.test(file.path) && !ENV_PLACEHOLDER_RE.test(file.path)) {
      const id = `github:committed_env:${file.path}`;
      // A committed env file holding only placeholders is untidy, not urgent.
      // Reserving CRITICAL for a file that actually carries a value keeps the
      // severity meaning something.
      // ...and the PATH decides how loudly. A committed env under a test or
      // scaffold path holding a real-looking value is reported one step
      // quieter, never dropped: the trade is a missed ESCALATION, never a
      // missed finding, and it is the same trade the secret scanner already
      // makes for fixtures.
      const quietPath = isTestPath(file.path) || isScaffoldPath(file.path) || /\.env\.(test|spec|ci)$/i.test(file.path);
      const hasSecret = envFileHasSecret(file.content);
      const live = hasSecret && envFileHasLiveCredential(file.path, file.content);
      // A value we cannot judge is a fact, not an issue: across the census,
      // CORPUS-5 and CORPUS-6 about 80 such files were read and none held a
      // live credential (local, CI, Docker and demo defaults, templates).
      const severity = live ? (quietPath ? "WARNING" : "CRITICAL") : "INFO";
      if (!seen.has(id)) {
        seen.add(id);
        findings.push({
          id,
          severity,
          title: `Environment file committed to the repo (${file.path})`,
          consequence: severity === "CRITICAL"
            ? `${file.path} is committed to source control and holds a value shaped like a live credential. Anyone with repository access, and anyone at all if it ever goes public, can read it. Remove the file, add it to .gitignore, and rotate every value in it.${describeShapes(file.content)}`
            : live
              ? `${file.path} sits under a test or example path but holds a value shaped like a live credential. If it is real, anyone with repository access can read it. Rotate it and keep test values synthetic.${describeShapes(file.content)}`
              : hasSecret
                ? `${file.path} is committed to source control and holds values under credential names. We could not tell whether they are live: they read like local or development defaults. If any is real, rotate it and add the file to .gitignore.${describeShapes(file.content)}`
                : `${file.path} is committed to source control. Its values are either placeholders or public by design, such as a NEXT_PUBLIC_ variable or a Supabase anon key, so nothing private is exposed here. Add it to .gitignore before something real is pasted into it.`,
          packageName: null, version: null, vulnId: null, cveId: null,
        });
      }
    }

    // A placeholder env file is documentation of which variables exist. Its
    // values are examples by definition, so it gets the same treatment as test
    // scaffolding: the generic assignment pattern proves nothing there, and a
    // synthetic-looking value is a placeholder rather than a leak. A
    // real-looking vendor-shaped key pasted into one is still reported.
    // `.env.test` is test scaffolding by name, and omitting it reported
    // outline's truncated placeholder PEM as a committed private key.
    const inTest =
      isTestPath(file.path) || ENV_PLACEHOLDER_RE.test(file.path) || isScaffoldPath(file.path) ||
      /\.env\.(test|spec|ci)$/i.test(file.path);

    for (const pat of SECRET_PATTERNS) {
      // The first match that is not filler: a docs sample's AKIA plus sixteen
      // X's must neither report nor hide a real key later in the same file.
      const match = [...file.content.matchAll(new RegExp(pat.re.source, pat.re.flags + "g"))]
        .find((m) => !isFillerKey(m[0]));
      if (!match || match.index === undefined) continue;
      if (pat.id === "private_key" && !hasParseablePrivateKey(file.content)) continue;

      // A fixture value in a test file is scaffolding, not a leak. Both
      // conditions are required: a synthetic-looking value in real code is
      // still worth saying out loud, and a real-looking value in a test file
      // is still a committed credential. Every remaining pattern here proves
      // a real credential's SHAPE, so a test file still gets the value check
      // below rather than a blanket skip.
      const line = lineOf(file.content, match.index);

      // A placeholder written INTO a comment is documentation, not a
      // credential. This file proved it on itself: the comment explaining that
      // AKIAIOSFODNN7EXAMPLE is Amazon's published example contains the string,
      // and the scanner reported its own explanation as a leaked AWS key.
      // A real-looking key in a comment still reports — people do paste those.
      if (pat.id !== "private_key" && isCommentLine(line) && looksSynthetic(match[0], line)) continue;

      // Scaffolding is wider than the test suite. `UNSUBSCRIBE_TOKEN_SECRET:
      // "dummy-secret"` in a CI workflow and `CUBEJS_API_SECRET:
      // build-time-placeholder` in a docker build were both reported as
      // CRITICAL committed credentials on repositories with thousands of stars.
      // A workflow file is exactly where a build-time stand-in belongs, and
      // nobody's real secret is spelled "dummy-secret".
      //
      // This deliberately does NOT extend to shipped application code, where a
      // hardcoded key is a hardcoded key however it is spelled -- the decision
      // recorded in "never downgrades a key in shipped code" and "it is real
      // code either way". The axis is whether the file ships, not whether the
      // value looks convincing.
      if (pat.id !== "private_key" && inTest && looksSynthetic(match[0], line)) continue;

      const id = `github:secret:${pat.id}:${file.path}`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        id,
        severity: inTest ? "WARNING" : "CRITICAL",
        title: inTest
          ? `Possible ${pat.label.replace(/^an? /, "")} in test file ${file.path}`
          : `Possible ${pat.label.replace(/^an? /, "")} committed in ${file.path}`,
        consequence: inTest
          ? `${file.path} is test scaffolding, and the value in it does not look manufactured. If the suite authenticates against something real, that credential is in source control and should be rotated and moved to an environment variable the suite reads.`
          : `${file.path} appears to contain ${pat.label}. Committed credentials are compromised the moment they're pushed; rotate it now and move it to a server-only environment variable.`,
        packageName: null, version: null, vulnId: null, cveId: null,
      });
    }
  }
  return findings;
}

// ── Dependencies ───────────────────────────────────────────────────────────
// Prefer the lockfile (exact, resolved versions — what OSV needs). Fall back to
// package.json ranges with the range operators stripped.
export function extractDependencies(packageJson: string, packageLock: string | null): Dep[] {
  // Keyed by name and version: a package installed at two versions (one
  // nested) is two things to check, and each must stay visible.
  const deps = new Map<string, Dep>();
  const add = (name: string, version: string) => deps.set(`${name}@${version}`, { name, version });

  if (packageLock) {
    try {
      const lock = JSON.parse(packageLock) as {
        packages?: Record<string, { version?: string }>;
        dependencies?: Record<string, { version?: string }>;
      };
      // npm lockfile v2/v3: keys like "node_modules/<name>" and nested
      // "node_modules/a/node_modules/<name>" — take the segment after the LAST
      // "node_modules/" so nested deps resolve to their real package name.
      for (const [key, val] of Object.entries(lock.packages ?? {})) {
        const idx = key.lastIndexOf("node_modules/");
        const name = idx >= 0 ? key.slice(idx + "node_modules/".length) : key;
        if (name && val?.version) add(name, val.version);
      }
      // v1 fallback
      for (const [name, val] of Object.entries(lock.dependencies ?? {})) {
        if (val?.version && ![...deps.values()].some((dep) => dep.name === name)) add(name, val.version);
      }
    } catch {
      /* fall through to package.json */
    }
  }

  if (deps.size === 0) {
    try {
      const pkg = JSON.parse(packageJson) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      for (const block of [pkg.dependencies, pkg.devDependencies]) {
        for (const [name, range] of Object.entries(block ?? {})) {
          const clean = range.replace(/^[\^~>=<\s]+/, "").trim();
          if (clean && /^\d/.test(clean)) add(name, clean);
        }
      }
    } catch {
      /* no parseable deps */
    }
  }

  return [...deps.values()];
}

// OSV vuln for a package, as returned by lib/deep/github.ts's queryOsv.
export interface OsvVuln {
  id: string; // OSV id, e.g. GHSA-xxxx
  cveId: string | null;
  summary: string;
  severity: Severity;
  // Smallest version that resolves this vuln (from OSV `affected` ranges), or
  // null if OSV didn't publish a fixed version — drives the auto-fix PR.
  fixedVersion: string | null;
}

// Pure: turn resolved (dep -> vulns) results into findings.
export function depFindings(results: { dep: Dep; vulns: OsvVuln[] }[]): GithubFinding[] {
  const findings: GithubFinding[] = [];
  for (const { dep, vulns } of results) {
    for (const v of vulns) {
      // Two installed versions with the same advisory are one thing to fix.
      if (findings.some((f) => f.id === `github:dep:${dep.name}:${v.id}`)) continue;
      findings.push({
        id: `github:dep:${dep.name}:${v.id}`,
        severity: v.severity,
        title: `${dep.name}@${dep.version}: ${v.cveId ?? v.id}`,
        consequence: `${v.summary} Update ${dep.name} past the vulnerable version.`,
        packageName: dep.name,
        version: dep.version,
        vulnId: v.id,
        cveId: v.cveId,
      });
    }
  }
  return findings;
}
