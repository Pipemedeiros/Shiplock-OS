import type { ArchiveFile } from "@/lib/deep/repoArchive";

/**
 * What the repository declares about the rest of the system.
 *
 * This is the collector behind the product's central claim: a repository is a
 * declaration of the system, so the auth provider, the database, the payment
 * processor and the object store can be read from source instead of asked for
 * in a setup wizard. `package.json` names Clerk; `schema.prisma` names the
 * tables; `.env.example` names the secrets that are supposed to exist.
 *
 * Detection is by DEPENDENCY FIRST, import second. A dependency in the manifest
 * is a fact about the project; an import is a fact about one file. Both are
 * recorded, because "declared but never imported" is itself worth knowing — it
 * is how an abandoned auth migration looks from the outside.
 *
 * Nothing here is a finding. It is context that later reasoning cites, and an
 * unrecognised stack must degrade to "we did not identify this" rather than to
 * an empty result that reads as "there is nothing here".
 */

export type StackKind =
  | "auth"
  | "database"
  | "payments"
  | "storage"
  | "email"
  | "hosting"
  | "ai"
  | "framework";

interface StackTool {
  id: string;
  name: string;
  kind: StackKind;
  /** How we know. Shown to the customer verbatim — every row names its source. */
  evidence: string;
  /** Files that import it, capped for display. */
  usedIn: string[];
}

interface Signature {
  id: string;
  name: string;
  kind: StackKind;
  /** npm package names. The primary signal. */
  packages: string[];
  /** Import specifiers, for tools reached without a dedicated package. */
  importPatterns?: RegExp;
  /** Environment variable names that give the tool away in .env.example. */
  envPatterns?: RegExp;
  /**
   * Config files whose mere presence names the tool.
   *
   * Hosting is the category that needs this. A repository deployed on Vercel
   * usually imports no Vercel package and sets no VERCEL_ variable of its own,
   * because the platform injects them at build time. `vercel.json` is often the
   * only thing in the repository that says so, and without this signal hosting
   * reads as unknown on an app that plainly has a host.
   */
  configFiles?: string[];
}

const SIGNATURES: Signature[] = [
  // ── auth ────────────────────────────────────────────────────────────────
  { id: "clerk", name: "Clerk", kind: "auth", packages: ["@clerk/nextjs", "@clerk/clerk-react", "@clerk/backend", "@clerk/clerk-sdk-node"], envPatterns: /CLERK_[A-Z_]+/ },
  { id: "supabase-auth", name: "Supabase Auth", kind: "auth", packages: ["@supabase/ssr", "@supabase/auth-helpers-nextjs"], importPatterns: /supabase\.auth\./ },
  { id: "nextauth", name: "NextAuth", kind: "auth", packages: ["next-auth", "@auth/core"], envPatterns: /NEXTAUTH_[A-Z_]+/ },
  { id: "better-auth", name: "Better Auth", kind: "auth", packages: ["better-auth"] },
  { id: "auth0", name: "Auth0", kind: "auth", packages: ["@auth0/nextjs-auth0", "auth0"], envPatterns: /AUTH0_[A-Z_]+/ },
  { id: "lucia", name: "Lucia", kind: "auth", packages: ["lucia"] },
  { id: "workos", name: "WorkOS", kind: "auth", packages: ["@workos-inc/node"] },
  { id: "firebase-auth", name: "Firebase Auth", kind: "auth", packages: ["firebase/auth"], importPatterns: /firebase\/auth|getAuth\(/ },
  { id: "cognito", name: "AWS Cognito", kind: "auth", packages: ["@aws-sdk/client-cognito-identity-provider", "amazon-cognito-identity-js"], envPatterns: /COGNITO_[A-Z_]+/ },
  { id: "okta", name: "Okta", kind: "auth", packages: ["@okta/okta-auth-js", "@okta/okta-sdk-nodejs"], envPatterns: /OKTA_[A-Z_]+/ },
  { id: "keycloak", name: "Keycloak", kind: "auth", packages: ["keycloak-js", "keycloak-connect"], envPatterns: /KEYCLOAK_[A-Z_]+/ },
  { id: "stytch", name: "Stytch", kind: "auth", packages: ["stytch", "@stytch/nextjs"], envPatterns: /STYTCH_[A-Z_]+/ },
  { id: "kinde", name: "Kinde", kind: "auth", packages: ["@kinde-oss/kinde-auth-nextjs"], envPatterns: /KINDE_[A-Z_]+/ },

  // ── database ────────────────────────────────────────────────────────────
  { id: "supabase", name: "Supabase", kind: "database", packages: ["@supabase/supabase-js"], envPatterns: /SUPABASE_[A-Z_]+/ },
  { id: "prisma", name: "Prisma", kind: "database", packages: ["@prisma/client", "prisma"] },
  { id: "drizzle", name: "Drizzle", kind: "database", packages: ["drizzle-orm"] },
  { id: "postgres", name: "Postgres", kind: "database", packages: ["pg", "postgres", "@neondatabase/serverless"], envPatterns: /DATABASE_URL|POSTGRES_[A-Z_]+/ },
  { id: "mongo", name: "MongoDB", kind: "database", packages: ["mongodb", "mongoose"], envPatterns: /MONGO(DB)?_(URI|URL)/ },
  { id: "planetscale", name: "PlanetScale", kind: "database", packages: ["@planetscale/database"] },
  { id: "firebase", name: "Firebase", kind: "database", packages: ["firebase", "firebase-admin"] },
  { id: "redis", name: "Redis", kind: "database", packages: ["redis", "ioredis", "@upstash/redis"], envPatterns: /REDIS_(URL|HOST|PASSWORD)|UPSTASH_REDIS_[A-Z_]+/ },
  { id: "mysql", name: "MySQL", kind: "database", packages: ["mysql", "mysql2"], envPatterns: /MYSQL_[A-Z_]+/ },
  { id: "sqlite", name: "SQLite", kind: "database", packages: ["better-sqlite3", "sqlite3", "@libsql/client"], envPatterns: /(TURSO|LIBSQL)_[A-Z_]+/ },
  { id: "convex", name: "Convex", kind: "database", packages: ["convex"], envPatterns: /CONVEX_[A-Z_]+/ },
  { id: "dynamodb", name: "DynamoDB", kind: "database", packages: ["@aws-sdk/client-dynamodb", "@aws-sdk/lib-dynamodb"] },

  // ── payments ────────────────────────────────────────────────────────────
  { id: "stripe", name: "Stripe", kind: "payments", packages: ["stripe", "@stripe/stripe-js"], envPatterns: /STRIPE_[A-Z_]+/ },
  { id: "paddle", name: "Paddle", kind: "payments", packages: ["@paddle/paddle-node-sdk"] },
  { id: "lemonsqueezy", name: "Lemon Squeezy", kind: "payments", packages: ["@lemonsqueezy/lemonsqueezy.js"] },
  { id: "polar", name: "Polar", kind: "payments", packages: ["@polar-sh/sdk"], envPatterns: /POLAR_[A-Z_]+/ },
  { id: "paypal", name: "PayPal", kind: "payments", packages: ["@paypal/checkout-server-sdk", "@paypal/react-paypal-js"], envPatterns: /PAYPAL_[A-Z_]+/ },
  { id: "razorpay", name: "Razorpay", kind: "payments", packages: ["razorpay"], envPatterns: /RAZORPAY_[A-Z_]+/ },

  // ── storage ─────────────────────────────────────────────────────────────
  { id: "s3", name: "Amazon S3", kind: "storage", packages: ["@aws-sdk/client-s3", "aws-sdk"], envPatterns: /AWS_(ACCESS|SECRET|S3)_[A-Z_]+/ },
  { id: "uploadthing", name: "UploadThing", kind: "storage", packages: ["uploadthing", "@uploadthing/react"] },
  { id: "cloudinary", name: "Cloudinary", kind: "storage", packages: ["cloudinary"] },
  { id: "r2", name: "Cloudflare R2", kind: "storage", packages: [], envPatterns: /R2_(ACCOUNT|ACCESS|SECRET)_[A-Z_]+/ },
  { id: "gcs", name: "Google Cloud Storage", kind: "storage", packages: ["@google-cloud/storage"] },
  { id: "azure-blob", name: "Azure Blob Storage", kind: "storage", packages: ["@azure/storage-blob"] },

  // ── email ───────────────────────────────────────────────────────────────
  { id: "resend", name: "Resend", kind: "email", packages: ["resend"], envPatterns: /RESEND_[A-Z_]+/ },
  { id: "sendgrid", name: "SendGrid", kind: "email", packages: ["@sendgrid/mail"] },
  { id: "postmark", name: "Postmark", kind: "email", packages: ["postmark"] },
  { id: "ses", name: "Amazon SES", kind: "email", packages: ["@aws-sdk/client-ses", "@aws-sdk/client-sesv2"] },
  { id: "mailgun", name: "Mailgun", kind: "email", packages: ["mailgun.js", "mailgun-js"], envPatterns: /MAILGUN_[A-Z_]+/ },
  { id: "loops", name: "Loops", kind: "email", packages: ["loops"], envPatterns: /LOOPS_[A-Z_]+/ },
  { id: "nodemailer", name: "Nodemailer", kind: "email", packages: ["nodemailer"], envPatterns: /SMTP_[A-Z_]+/ },

  // ── framework and hosting ───────────────────────────────────────────────
  { id: "next", name: "Next.js", kind: "framework", packages: ["next"] },
  { id: "remix", name: "Remix", kind: "framework", packages: ["@remix-run/node", "@remix-run/react"] },
  { id: "express", name: "Express", kind: "framework", packages: ["express"] },
  { id: "fastify", name: "Fastify", kind: "framework", packages: ["fastify"] },
  { id: "nest", name: "NestJS", kind: "framework", packages: ["@nestjs/core"] },
  { id: "vercel", name: "Vercel", kind: "hosting", packages: ["@vercel/analytics", "@vercel/blob", "@vercel/kv", "@vercel/postgres"], envPatterns: /VERCEL_[A-Z_]+/, configFiles: ["vercel.json", ".vercel/project.json"] },
  { id: "cloudflare", name: "Cloudflare", kind: "hosting", packages: ["wrangler", "@cloudflare/workers-types", "@cloudflare/next-on-pages"], envPatterns: /CLOUDFLARE_[A-Z_]+|CF_(API|ACCOUNT)_[A-Z_]+/, configFiles: ["wrangler.toml", "wrangler.jsonc", "wrangler.json"] },
  { id: "aws", name: "AWS", kind: "hosting", packages: ["aws-cdk-lib", "@aws-sdk/client-lambda", "serverless"], envPatterns: /AWS_(REGION|LAMBDA|EXECUTION)_[A-Z_]*/, configFiles: ["serverless.yml", "template.yaml", "samconfig.toml"] },
  { id: "gcp", name: "Google Cloud", kind: "hosting", packages: ["@google-cloud/functions-framework", "@google-cloud/run"], envPatterns: /(GCLOUD|GOOGLE_CLOUD)_[A-Z_]+/, configFiles: ["app.yaml", "cloudbuild.yaml"] },
  { id: "netlify", name: "Netlify", kind: "hosting", packages: ["@netlify/functions", "netlify-cli"], envPatterns: /NETLIFY_[A-Z_]+/, configFiles: ["netlify.toml"] },
  { id: "railway", name: "Railway", kind: "hosting", packages: [], envPatterns: /RAILWAY_[A-Z_]+/, configFiles: ["railway.json", "railway.toml"] },
  { id: "render", name: "Render", kind: "hosting", packages: [], envPatterns: /RENDER_[A-Z_]+/, configFiles: ["render.yaml"] },
  { id: "fly", name: "Fly.io", kind: "hosting", packages: [], envPatterns: /FLY_(APP_NAME|REGION|ALLOC_ID)/, configFiles: ["fly.toml"] },
  { id: "azure", name: "Azure", kind: "hosting", packages: ["@azure/functions", "@azure/identity"], envPatterns: /AZURE_[A-Z_]+/ },

  // AI providers. A category the ICP is defined by (Anthropic 64%, OpenAI 52%,
  // Gemini 44% in the 2026 survey) and that we did not name at all until now.
  // The security surface is direct: a committed provider key is billing theft,
  // and these keys are among the most commonly leaked.
  { id: "anthropic", name: "Anthropic", kind: "ai", packages: ["@anthropic-ai/sdk"], envPatterns: /ANTHROPIC_[A-Z_]+/ },
  { id: "openai", name: "OpenAI", kind: "ai", packages: ["openai"], envPatterns: /OPENAI_[A-Z_]+/ },
  { id: "gemini", name: "Google Gemini", kind: "ai", packages: ["@google/generative-ai", "@google/genai"], envPatterns: /GEMINI_[A-Z_]+|GOOGLE_(GENAI|API)_KEY/ },
  { id: "vercel-ai", name: "Vercel AI SDK", kind: "ai", packages: ["ai", "@ai-sdk/openai", "@ai-sdk/anthropic"] },
  { id: "replicate", name: "Replicate", kind: "ai", packages: ["replicate"], envPatterns: /REPLICATE_[A-Z_]+/ },
  { id: "langchain", name: "LangChain", kind: "ai", packages: ["langchain", "@langchain/core"] },
];

/**
 * Files that describe code rather than being it.
 *
 * Excluded from import detection because a test fixture, a mock or a detector's
 * own signature list mentions package names it does not use. Dogfooding this
 * against ShipLock's own repository reported Clerk, Auth0, Lucia, WorkOS,
 * Prisma, MongoDB and Firebase -- none of which it uses -- entirely from
 * strings inside this file and its tests.
 */
const NOT_APPLICATION_CODE = /(^|\/)(.*\.(test|spec)\.[cm]?[jt]sx?|__tests__|__mocks__|fixtures?|lib\/agent\/stack\.ts)($|\/)/;

/** Dependency names from a package.json, both prod and dev. */
export function readDependencies(packageJson: string | undefined): Set<string> {
  if (!packageJson) return new Set();
  try {
    const parsed = JSON.parse(packageJson) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    return new Set([
      ...Object.keys(parsed.dependencies ?? {}),
      ...Object.keys(parsed.devDependencies ?? {}),
    ]);
  } catch {
    // A malformed manifest is a fact about the repo, not a reason to throw. We
    // fall through to import-based detection rather than reporting no stack.
    return new Set();
  }
}

/** True when `content` imports or requires `pkg`, subpaths included. */
function importsPackage(content: string, pkg: string): boolean {
  const escaped = pkg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const spec = `${escaped}(?:/[\\w./-]*)?`;
  return new RegExp(
    `(?:from\\s*|require\\(\\s*|import\\(\\s*)["'\`]${spec}["'\`]|^\\s*import\\s+["'\`]${spec}["'\`]`,
    "m",
  ).test(content);
}

export interface StackReport {
  tools: StackTool[];
  /** True when we could not identify an auth provider — changes what we can claim. */
  authUnknown: boolean;
  /** True when we could not identify a database. */
  databaseUnknown: boolean;
}

export interface RouteAnalysisSupport {
  level: "deep" | "inventory_only";
  framework: "nextjs" | "unsupported_or_unknown";
  reason: string;
}

/** The current route reasoner is intentionally narrower than stack detection.
 * Detecting Express, Nest or Firebase is inventory; it is not evidence that we
 * understand that framework's authorization paths. */
export function routeAnalysisSupport(stack: StackReport): RouteAnalysisSupport {
  if (stack.tools.some((tool) => tool.id === "next")) {
    return {
      level: "deep",
      framework: "nextjs",
      reason: "Next.js App Router and Pages API routes in JavaScript or TypeScript are supported.",
    };
  }
  return {
    level: "inventory_only",
    framework: "unsupported_or_unknown",
    reason: "Deep route authorization analysis currently supports Next.js App Router and Pages API routes only.",
  };
}

/**
 * Identifies the stack from a repository's files.
 *
 * `usedIn` is capped at five files per tool: the list exists to let a customer
 * verify the claim, not to reproduce the import graph on screen.
 */
export function detectStack(files: ArchiveFile[]): StackReport {
  const byPath = new Map(files.map((f) => [f.path, f]));
  const deps = readDependencies(byPath.get("package.json")?.content);

  const envFiles = files.filter((f) => /(^|\/)\.env/.test(f.path));
  const envText = envFiles.map((f) => f.content).join("\n");

  const sourceFiles = files.filter(
    (f) => /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.path) && !NOT_APPLICATION_CODE.test(f.path),
  );

  const tools: StackTool[] = [];

  for (const sig of SIGNATURES) {
    const matchedPackage = sig.packages.find((p) => deps.has(p));

    const usedIn: string[] = [];
    for (const file of sourceFiles) {
      // A real import, not a substring. Matching any occurrence of the package
      // name meant every mention in a comment or a string literal counted as
      // usage, which is how a repo that merely NAMES a library was reported as
      // depending on it.
      const importsIt =
        sig.packages.some((p) => importsPackage(file.content, p)) ||
        (sig.importPatterns?.test(file.content) ?? false);
      if (importsIt) usedIn.push(file.path);
      if (usedIn.length >= 5) break;
    }

    const envHit = sig.envPatterns?.test(envText) ?? false;
    const configFile = sig.configFiles?.find((name) => byPath.has(name)) ?? null;

    if (!matchedPackage && usedIn.length === 0 && !envHit && !configFile) continue;

    // Order matters: the manifest is the strongest evidence, then real imports,
    // then a declared environment variable. Each is said plainly enough that a
    // customer can check it.
    const evidence = matchedPackage
      ? `"${matchedPackage}" in package.json${usedIn.length ? `, imported in ${usedIn.length === 5 ? "5+" : usedIn.length} file${usedIn.length === 1 ? "" : "s"}` : ", not imported anywhere we read"}`
      : usedIn.length
        ? `imported in ${usedIn.length === 5 ? "5+" : usedIn.length} file${usedIn.length === 1 ? "" : "s"}`
        : configFile
          ? `${configFile} in the repository`
          : "named in an environment file";

    tools.push({ id: sig.id, name: sig.name, kind: sig.kind, evidence, usedIn });
  }

  return {
    tools,
    authUnknown: !tools.some((t) => t.kind === "auth"),
    databaseUnknown: !tools.some((t) => t.kind === "database"),
  };
}
