import { describe, expect, it } from "vitest";
import type { RepoFile } from "@/lib/deep/githubScan";
import { collectRoutes } from "@/lib/graph/routeInventory";
import { guardHypotheses, type Hypothesis, type ReconIndex } from "./attackGuard";
import { buildFindings } from "./findings";
import { mintOf, oneIdAccess, possessionGates, renderPossessionGate } from "./possessionGate";

/**
 * THE INVARIANT THIS CLASS IS NOT ALLOWED TO BREAK.
 *
 * corpus-b's /api/teams/[teamId]/documents/document-processing-status is a
 * CONFIRMED TRUE POSITIVE (the frozen labels in docs/CORPUS.json). It takes one
 * request id, looks the row up by primary key, answers 404 on null, and does
 * nothing else -- which passes every readable test a possession gate could
 * use. It is a forgotten auth check: its siblings authenticate, its own
 * [teamId] segment is never read, and its only caller is the signed-in
 * dashboard. None of that is in the route's dataflow.
 *
 * So the possession-gate class may never capture it. If a change to
 * possessionGate.ts makes this test fail, the change is wrong and must be
 * narrowed, not this test.
 *
 * Fixtures are shape copies, not the corpus source: the pinned archives are not
 * available to CI.
 */

const SCHEMA = `
model DocumentVersion {
  id        String  @id @default(cuid())
  numPages  Int?
  hasPages  Boolean @default(false)
}

model Link {
  id    String @id @default(cuid())
  views View[]
}

model Document {
  id    String @id @default(cuid())
  views View[]
}

model View {
  id         String   @id @default(cuid())
  link       Link     @relation(fields: [linkId], references: [id])
  linkId     String
  document   Document? @relation(fields: [documentId], references: [id])
  documentId String?
}
`;

const PROCESSING_STATUS = `import { NextApiRequest, NextApiResponse } from "next";
import prisma from "@/lib/prisma";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { documentVersionId } = req.query as { documentVersionId: string };

  const documentVersion = await prisma.documentVersion.findUnique({
    where: { id: documentVersionId },
    select: { numPages: true, hasPages: true },
  });

  if (!documentVersion) {
    return res.status(404).end();
  }

  res.status(200).json({ totalPages: documentVersion.numPages, hasPages: documentVersion.hasPages });
}
`;

const REPORT = `import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import prisma from "@/lib/prisma";
import { redis } from "@/lib/redis";

const bodyValidation = z.object({ linkId: z.string(), documentId: z.string(), viewId: z.string() });

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.status(405).json({ message: "Method Not Allowed" });
    return;
  }

  const { linkId, documentId, viewId } = req.body as { linkId: string; documentId: string; viewId: string };
  const result = bodyValidation.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ message: "Invalid request" });
  }

  try {
    const view = await prisma.view.findUnique({
      where: { id: viewId, linkId, documentId },
      select: { id: true },
    });

    if (!view) {
      return res.status(400).json({ status: "error", message: "View not found" });
    }
  } catch (err) {
    return res.status(500).json({ status: "error", message: (err as Error).message });
  }

  await redis.sadd("report:doc_" + documentId, "view_" + viewId);
  return res.status(200).json({ status: "success" });
}
`;

function pipeline(files: RepoFile[], hypothesis: Hypothesis) {
  const routes = collectRoutes(files);
  const byPath = new Map(files.map((f) => [f.path, f]));
  const gates = possessionGates(routes, byPath);
  const oneId = oneIdAccess(routes, byPath);
  const recon: ReconIndex = {
    entries: new Set(routes.map((r) => r.path)),
    files: new Set(files.map((f) => f.path)),
    tables: new Set(routes.flatMap((r) => r.tables)),
    routes: new Map(routes.map((r) => [r.path, r])),
    possessionGates: gates,
  };
  const guarded = guardHypotheses([hypothesis], recon);
  const findings = buildFindings({
    admitted: guarded.admitted,
    deterministic: [],
    routes,
    stack: { tools: [], databaseUnknown: false } as never,
    repositoryId: "r",
    hasDatabase: false,
    possessionGates: gates,
    oneIdAccess: oneId,
  });
  return { routes, gates, oneId, guarded, findings };
}

const PROCESSING_FILE = "pages/api/teams/[teamId]/documents/document-processing-status.ts";
const REPORT_FILE = "pages/api/report.ts";

// Q21 (Felipe, 2026-09-28): an anonymous route whose only way in is a
// random-minted request id is capped at WARNING, never removed. This route was
// pinned CRITICAL until that decision; it stays visible and assessed.
describe("INVARIANT: document-processing-status stays visible, capped at WARNING (Q21)", () => {
  const files: RepoFile[] = [
    { path: "prisma/schema/schema.prisma", content: SCHEMA },
    { path: PROCESSING_FILE, content: PROCESSING_STATUS },
  ];
  const hypothesis: Hypothesis = {
    entry: "/api/teams/[teamId]/documents/document-processing-status",
    attackClass: "missing_authentication",
    title: "Document processing status is readable without signing in",
    consequence: "Anyone can read page counts for a document version by id.",
    citedFiles: [PROCESSING_FILE],
  };

  it("is still a fully assessed anonymous route, so the invariant is not vacuous", () => {
    const { routes } = pipeline(files, hypothesis);
    const route = routes.find((r) => r.file === PROCESSING_FILE);
    expect(route).toBeDefined();
    expect(route!.identityReadable).toBe(true);
    expect(route!.authenticated).toBe(false);
    expect(route!.machineGated).toBe(false);
    expect(route!.tables).toEqual(["documentVersion"]);
  });

  it("carries no possession gate", () => {
    const { gates } = pipeline(files, hypothesis);
    expect(gates.has("/api/teams/[teamId]/documents/document-processing-status")).toBe(false);
  });

  it("is admitted as missing_authentication, capped at WARNING, naming the id and its mint", () => {
    const { guarded, findings, oneId } = pipeline(files, hypothesis);
    expect(guarded.admitted.map((h) => h.attackClass)).toEqual(["missing_authentication"]);
    expect(findings).toHaveLength(1);
    expect(findings[0].attackClass).toBe("missing_authentication");
    expect(findings[0].severity).toBe("WARNING");
    expect(findings[0].id).toBe("agent:missing_authentication:/api/teams/[teamId]/documents/document-processing-status");
    expect(oneId.get("/api/teams/[teamId]/documents/document-processing-status")).toMatchObject({ param: "documentVersionId", field: "id", bindings: [] });
    expect(findings[0].claims).toContainEqual(expect.objectContaining({
      claim: expect.stringMatching(/only way in is a DocumentVersion id \(documentVersionId\).*cuid\(\)/), verified: true }));
  });

  it("without a random mint the cap does not apply: an autoincrement id stays CRITICAL", () => {
    const sequential = SCHEMA.replace("id        String  @id @default(cuid())\n  numPages", "id        Int     @id @default(autoincrement())\n  numPages");
    expect(sequential).not.toBe(SCHEMA);
    const { findings, oneId } = pipeline([{ path: "prisma/schema/schema.prisma", content: sequential }, { path: PROCESSING_FILE, content: PROCESSING_STATUS }], hypothesis);
    expect(oneId.size).toBe(0);
    expect(findings[0].severity).toBe("CRITICAL");
  });

  it("a bound gate is not one-id access: the report shape is possession_gated, not capped", () => {
    const { oneId } = pipeline([...files, { path: REPORT_FILE, content: REPORT }], hypothesis);
    expect(oneId.has("/api/report")).toBe(false);
  });

  // The positive control. Without it the three tests above pass for a rule that
  // captures nothing at all, which is the trivial pass this file must not hide.
  it("CONTROL: the report shape in the same schema does move, so the rule is not simply inert", () => {
    const withReport: RepoFile[] = [...files, { path: REPORT_FILE, content: REPORT }];
    const { gates, findings } = pipeline(withReport, {
      entry: "/api/report",
      attackClass: "missing_authentication",
      title: "Report endpoint accepts anonymous submissions",
      consequence: "Anyone holding a view id can file an abuse report.",
      citedFiles: [REPORT_FILE],
    });
    expect(gates.has("/api/report")).toBe(true);
    expect(findings[0].attackClass).toBe("possession_gated");
    expect(findings[0].severity).toBe("INFO");
  });
});

// Q15 (2026-09-28): Sonnet 5 phrased these share-link claims as
// missing_authorization ("not scoped by team"). On a route read as anonymous
// there is no caller to scope by, so it is the same wrong sentence and gets the
// same one rewording, only where a gate was read.
describe("missing_authorization on a gated anonymous route is reworded the same way (Q15)", () => {
  const schemaOnly: RepoFile = { path: "prisma/schema/schema.prisma", content: SCHEMA };
  it("is possession_gated, INFO, where a gate was read", () => {
    const { guarded, findings } = pipeline([schemaOnly, { path: REPORT_FILE, content: REPORT }], {
      entry: "/api/report",
      attackClass: "missing_authorization",
      title: "Report endpoint exposes view data across tenants",
      consequence: "View records can be reported on without any tenant restriction.",
      citedFiles: [REPORT_FILE],
    });
    expect(guarded.admitted.map((h) => h.attackClass)).toEqual(["possession_gated"]);
    expect(findings[0].severity).toBe("INFO");
  });

  it("INVARIANT: stays missing_authorization, and visible, where no gate was read", () => {
    const { guarded, findings } = pipeline([schemaOnly, { path: PROCESSING_FILE, content: PROCESSING_STATUS }], {
      entry: "/api/teams/[teamId]/documents/document-processing-status",
      attackClass: "missing_authorization",
      title: "Document processing status readable without team scoping",
      consequence: "A caller can poll processing status of other teams' document versions.",
      citedFiles: [PROCESSING_FILE],
    });
    expect(guarded.admitted.map((h) => h.attackClass)).toEqual(["missing_authorization"]);
    expect(findings).toHaveLength(1);
  });
});

describe("RULE 6: the id needs a random mint the schema states", () => {
  it("names the strength of each recognised default and refuses everything else", () => {
    expect(mintOf("cuid()")).toMatch(/version 1 cuid/);
    expect(mintOf("uuid()")).toMatch(/122 random bits/);
    expect(mintOf('dbgenerated("gen_random_uuid()")')).toMatch(/122 random bits/);
    expect(mintOf("autoincrement()")).toBeNull();
    expect(mintOf("sequence()")).toBeNull();
    expect(mintOf("now()")).toBeNull();
    expect(mintOf(null)).toBeNull();
  });

  const viewSchema = (idLine: string) => `
model Link {
  id    String @id @default(cuid())
}
model View {
  ${idLine}
  link   Link   @relation(fields: [linkId], references: [id])
  linkId String
  slug   String @unique
}
`;
  const handler = (where: string) => `import prisma from "@/lib/prisma";
export default async function handler(req, res) {
  const { viewId, linkId, slug } = req.body;
  const view = await prisma.view.findUnique({ where: ${where} });
  if (!view) {
    return res.status(404).end();
  }
  return res.status(200).json(view);
}
`;
  const gatesFor = (schema: string, src: string) => {
    const files: RepoFile[] = [
      { path: "prisma/schema.prisma", content: schema },
      { path: "pages/api/thing.ts", content: src },
    ];
    return possessionGates(collectRoutes(files), new Map(files.map((f) => [f.path, f])));
  };

  it("a cuid id bound to a second request value is a gate (the control for the refusals below)", () => {
    expect(gatesFor(viewSchema("id String @id @default(cuid())"), handler("{ id: viewId, linkId }")).has("/api/thing")).toBe(true);
  });

  it("an autoincrement id is never a possession gate", () => {
    expect(gatesFor(viewSchema("id Int @id @default(autoincrement())"), handler("{ id: viewId, linkId }")).size).toBe(0);
  });

  it("an id with no readable default is never a possession gate", () => {
    expect(gatesFor(viewSchema("id String @id"), handler("{ id: viewId, linkId }")).size).toBe(0);
  });

  it("a slug is never a possession gate, even when unique and bound", () => {
    expect(gatesFor(viewSchema("id String @id @default(cuid())"), handler("{ slug, linkId }")).size).toBe(0);
  });

  it("a schema declaring the same model twice, differently, has no readable mint", () => {
    const twice = viewSchema("id String @id @default(cuid())") + viewSchema("id Int @id @default(autoincrement())").replace("model Link {\n  id    String @id @default(cuid())\n}", "");
    expect(gatesFor(twice, handler("{ id: viewId, linkId }")).size).toBe(0);
  });
});

describe("RULE 3: a one-id check is not a gate, however it is enforced", () => {
  it("record_reaction's shape, a foreign-key-only create naming one resource, stays a critical", () => {
    const files: RepoFile[] = [
      { path: "prisma/schema.prisma", content: `${SCHEMA}\nmodel Reaction {\n  id     String @id @default(cuid())\n  view   View   @relation(fields: [viewId], references: [id])\n  viewId String\n}\n` },
      {
        path: "pages/api/record_reaction.ts",
        content: `import prisma from "@/lib/prisma";
export default async function handle(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ message: "Method Not Allowed" });
    return;
  }
  const { viewId, pageNumber, type } = req.body;
  try {
    const reaction = await prisma.reaction.create({ data: { viewId, pageNumber, type } });
    res.status(200).json({ message: "Reaction recorded" });
    return;
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
    return;
  }
}
`,
      },
    ];
    expect(possessionGates(collectRoutes(files), new Map(files.map((f) => [f.path, f]))).size).toBe(0);
  });
});

describe("RULES 2, 4, 5: what the gate must dominate", () => {
  const files = (src: string, path = "pages/api/report.ts"): RepoFile[] => [
    { path: "prisma/schema/schema.prisma", content: SCHEMA },
    { path, content: src },
  ];
  const gated = (fs: RepoFile[]) => possessionGates(collectRoutes(fs), new Map(fs.map((f) => [f.path, f]))).has("/api/report");

  it("a null check that throws instead of returning is not a gate: a catch can swallow it", () => {
    expect(gated(files(REPORT.replace(`return res.status(400).json({ status: "error", message: "View not found" });`, `throw new Error("View not found");`)))).toBe(false);
  });

  it("data touched before the gate means no gate", () => {
    expect(gated(files(REPORT.replace(`  try {\n    const view`, `  await redis.incr("reports");\n  try {\n    const view`)))).toBe(false);
  });

  it("a catch that does anything but answer means no gate: it also runs before the gate holds", () => {
    expect(gated(files(REPORT.replace(`return res.status(500).json({ status: "error", message: (err as Error).message });`, `await notify(err);\n    return res.status(500).end();`)))).toBe(false);
  });

  it("a handler passed through a wrapper is not read here, so it has no gate", () => {
    const wrapped = REPORT.replace("export default async function handler(req: NextApiRequest, res: NextApiResponse) {", "async function handler(req: NextApiRequest, res: NextApiResponse) {") + "\nexport default withRateLimit(handler);\n";
    expect(gated(files(wrapped))).toBe(false);
  });

  it("a handler that delegates its body to another module has no gate", () => {
    expect(gated(files(`import { handleRoute } from "@/lib/report-route";\nexport default async function handler(req, res) {\n  return handleRoute(req, res);\n}\n`))).toBe(false);
  });

  it("a row found by one id binds a later lookup (feedback's shape)", () => {
    const schema = `${SCHEMA}\nmodel Feedback {\n  id     String @id @default(cuid())\n  link   Link   @relation(fields: [linkId], references: [id])\n  linkId String\n}\n`;
    const src = `import prisma from "@/lib/prisma";
export default async function handle(req, res) {
  if (req.method === "POST") {
    const { answer, feedbackId, viewId } = req.body;
    try {
      const feedback = await prisma.feedback.findUnique({ where: { id: feedbackId } });
      if (!feedback) {
        return res.status(404).json({ error: "Feedback not found" });
      }
      const view = await prisma.view.findUnique({ where: { id: viewId, linkId: feedback.linkId } });
      if (!view) {
        return res.status(404).json({ error: "View not found" });
      }
      await prisma.feedbackResponse.create({ data: { feedbackId, viewId, answer } });
      return res.status(200).json({ message: "ok" });
    } catch (error) {
      return res.status(500).json({ message: "Internal Server Error" });
    }
  }
  res.setHeader("Allow", ["POST"]);
  return res.status(405).end();
}
`;
    const fs: RepoFile[] = [{ path: "prisma/schema.prisma", content: schema }, { path: "pages/api/feedback/index.ts", content: src }];
    const gates = possessionGates(collectRoutes(fs), new Map(fs.map((f) => [f.path, f])));
    expect(gates.get("/api/feedback")?.bindings.map((b) => b.source)).toEqual(["the linkId of the Feedback found by feedbackId"]);
  });

  it("the same row released before the second lookup means no gate", () => {
    const schema = `${SCHEMA}\nmodel Feedback {\n  id     String @id @default(cuid())\n  link   Link   @relation(fields: [linkId], references: [id])\n  linkId String\n}\n`;
    const src = `import prisma from "@/lib/prisma";
export default async function handle(req, res) {
  const { feedbackId, viewId } = req.body;
  const feedback = await prisma.feedback.findUnique({ where: { id: feedbackId } });
  if (!feedback) {
    return res.status(404).json(feedback);
  }
  res.setHeader("X-Feedback", feedback.linkId);
  const view = await prisma.view.findUnique({ where: { id: viewId, linkId: feedback.linkId } });
  if (!view) {
    return res.status(404).end();
  }
  return res.status(200).json(view);
}
`;
    const fs: RepoFile[] = [{ path: "prisma/schema.prisma", content: schema }, { path: "pages/api/feedback/index.ts", content: src }];
    expect(possessionGates(collectRoutes(fs), new Map(fs.map((f) => [f.path, f]))).size).toBe(0);
  });
});

describe("the guard: possession_gated is never the model's word", () => {
  const files: RepoFile[] = [
    { path: "prisma/schema/schema.prisma", content: SCHEMA },
    { path: PROCESSING_FILE, content: PROCESSING_STATUS },
  ];

  it("is refused where no gate was read, even on an anonymous route", () => {
    const { guarded } = pipeline(files, {
      entry: "/api/teams/[teamId]/documents/document-processing-status",
      attackClass: "possession_gated",
      title: "Gated by possession",
      consequence: "Anyone holding the id can read it.",
      citedFiles: [PROCESSING_FILE],
    });
    expect(guarded.admitted).toHaveLength(0);
    expect(guarded.rejected[0].reason).toBe("no possession gate was read on this route");
    expect(guarded.unassessed).toHaveLength(0);
  });

  it("a guard handed no gate map rewords nothing", () => {
    const withReport: RepoFile[] = [...files, { path: REPORT_FILE, content: REPORT }];
    const routes = collectRoutes(withReport);
    const recon: ReconIndex = {
      entries: new Set(routes.map((r) => r.path)),
      files: new Set(withReport.map((f) => f.path)),
      tables: new Set(routes.flatMap((r) => r.tables)),
      routes: new Map(routes.map((r) => [r.path, r])),
    };
    const out = guardHypotheses(
      [{ entry: "/api/report", attackClass: "missing_authentication", title: "t", consequence: "c", citedFiles: [REPORT_FILE] }],
      recon,
    );
    expect(out.admitted.map((h) => h.attackClass)).toEqual(["missing_authentication"]);
  });
});

describe("the wording a customer reads", () => {
  const withReport: RepoFile[] = [
    { path: "prisma/schema/schema.prisma", content: SCHEMA },
    { path: REPORT_FILE, content: REPORT },
  ];
  const gate = () => {
    const gates = possessionGates(collectRoutes(withReport), new Map(withReport.map((f) => [f.path, f])));
    return gates.get("/api/report")!;
  };

  it("names the lookup, the binding and the mint with file and line, and says what was not read", () => {
    const r = renderPossessionGate(gate());
    const text = [r.title, r.consequence, ...r.claims.map((c) => c.claim)].join("\n");
    expect(text).toContain(`${REPORT_FILE}:`);
    expect(text).toContain("linkId and documentId");
    expect(text).toContain("cuid()");
    expect(r.claims.filter((c) => !c.verified).map((c) => c.claim)).toEqual([expect.stringMatching(/^Not read: whether a View id is ever shown/)]);
  });

  it("carries no critical vocabulary, no hedge words, no dashes and no adversarial framing", () => {
    const r = renderPossessionGate(gate());
    const text = [r.title, r.consequence, ...r.claims.map((c) => c.claim)].join("\n");
    expect(text).not.toMatch(/attacker|exploit|vulnerab|critical|may be|might|could be|possibly|unauthenticated/i);
    expect(text).not.toMatch(/[–—]| - /);
  });
});

describe("a missing gate map never makes a finding vanish", () => {
  it("renders a possession_gated admission with no gate as the critical it was reworded from", () => {
    const findings = buildFindings({
      admitted: [{ entry: "/api/report", attackClass: "possession_gated", title: "Report endpoint is open", consequence: "Anyone can file a report.", citedFiles: [REPORT_FILE] }],
      deterministic: [],
      routes: [],
      stack: { tools: [], databaseUnknown: false } as never,
      repositoryId: "r",
      hasDatabase: false,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].attackClass).toBe("missing_authentication");
    expect(findings[0].severity).toBe("CRITICAL");
  });
});
