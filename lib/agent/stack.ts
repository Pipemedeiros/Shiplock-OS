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

export type StackKind = "auth" | "database" | "payments" | "storage" | "email" | "hosting" | "framework";

export interface StackTool {
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

  // ── database ────────────────────────────────────────────────────────────
  { id: "supabase", name: "Supabase", kind: "database", packages: ["@supabase/supabase-js"], envPatterns: /SUPABASE_[A-Z_]+/ },
  { id: "prisma", name: "Prisma", kind: "database", packages: ["@prisma/client", "prisma"] },
  { id: "drizzle", name: "Drizzle", kind: "database", packages: ["drizzle-orm"] },
  { id: "postgres", name: "Postgres", kind: "database", packages: ["pg", "postgres", "@neondatabase/serverless"], envPatterns: /DATABASE_URL|POSTGRES_[A-Z_]+/ },
  { id: "mongo", name: "MongoDB", kind: "database", packages: ["mongodb", "mongoose"], envPatterns: /MONGO(DB)?_(URI|URL)/ },
  { id: "planetscale", name: "PlanetScale", kind: "database", packages: ["@planetscale/database"] },
  { id: "firebase", name: "Firebase", kind: "database", packages: ["firebase", "firebase-admin"] },

  // ── payments ────────────────────────────────────────────────────────────
  { id: "stripe", name: "Stripe", kind: "payments", packages: ["stripe", "@stripe/stripe-js"], envPatterns: /STRIPE_[A-Z_]+/ },
  { id: "paddle", name: "Paddle", kind: "payments", packages: ["@paddle/paddle-node-sdk"] },
  { id: "lemonsqueezy", name: "Lemon Squeezy", kind: "payments", packages: ["@lemonsqueezy/lemonsqueezy.js"] },

  // ── storage ─────────────────────────────────────────────────────────────
  { id: "s3", name: "Amazon S3", kind: "storage", packages: ["@aws-sdk/client-s3", "aws-sdk"], envPatterns: /AWS_(ACCESS|SECRET|S3)_[A-Z_]+/ },
  { id: "uploadthing", name: "UploadThing", kind: "storage", packages: ["uploadthing", "@uploadthing/react"] },
  { id: "cloudinary", name: "Cloudinary", kind: "storage", packages: ["cloudinary"] },
  { id: "r2", name: "Cloudflare R2", kind: "storage", packages: [], envPatterns: /R2_(ACCOUNT|ACCESS|SECRET)_[A-Z_]+/ },

  // ── email ───────────────────────────────────────────────────────────────
  { id: "resend", name: "Resend", kind: "email", packages: ["resend"], envPatterns: /RESEND_[A-Z_]+/ },
  { id: "sendgrid", name: "SendGrid", kind: "email", packages: ["@sendgrid/mail"] },
  { id: "postmark", name: "Postmark", kind: "email", packages: ["postmark"] },

  // ── framework and hosting ───────────────────────────────────────────────
  { id: "next", name: "Next.js", kind: "framework", packages: ["next"] },
  { id: "remix", name: "Remix", kind: "framework", packages: ["@remix-run/node", "@remix-run/react"] },
  { id: "express", name: "Express", kind: "framework", packages: ["express"] },
  { id: "fastify", name: "Fastify", kind: "framework", packages: ["fastify"] },
  { id: "nest", name: "NestJS", kind: "framework", packages: ["@nestjs/core"] },
  { id: "vercel", name: "Vercel", kind: "hosting", packages: ["@vercel/analytics", "@vercel/blob"] },
];

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

export interface StackReport {
  tools: StackTool[];
  /** True when we could not identify an auth provider — changes what we can claim. */
  authUnknown: boolean;
  /** True when we could not identify a database. */
  databaseUnknown: boolean;
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

  const sourceFiles = files.filter((f) => /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.path));

  const tools: StackTool[] = [];

  for (const sig of SIGNATURES) {
    const matchedPackage = sig.packages.find((p) => deps.has(p));

    const usedIn: string[] = [];
    for (const file of sourceFiles) {
      const importsIt =
        sig.packages.some((p) => file.content.includes(`"${p}`) || file.content.includes(`'${p}`)) ||
        (sig.importPatterns?.test(file.content) ?? false);
      if (importsIt) usedIn.push(file.path);
      if (usedIn.length >= 5) break;
    }

    const envHit = sig.envPatterns?.test(envText) ?? false;

    if (!matchedPackage && usedIn.length === 0 && !envHit) continue;

    // Order matters: the manifest is the strongest evidence, then real imports,
    // then a declared environment variable. Each is said plainly enough that a
    // customer can check it.
    const evidence = matchedPackage
      ? `"${matchedPackage}" in package.json${usedIn.length ? `, imported in ${usedIn.length === 5 ? "5+" : usedIn.length} file${usedIn.length === 1 ? "" : "s"}` : ", not imported anywhere we read"}`
      : usedIn.length
        ? `imported in ${usedIn.length === 5 ? "5+" : usedIn.length} file${usedIn.length === 1 ? "" : "s"}`
        : "named in an environment file";

    tools.push({ id: sig.id, name: sig.name, kind: sig.kind, evidence, usedIn });
  }

  return {
    tools,
    authUnknown: !tools.some((t) => t.kind === "auth"),
    databaseUnknown: !tools.some((t) => t.kind === "database"),
  };
}
