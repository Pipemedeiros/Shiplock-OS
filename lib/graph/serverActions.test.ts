import { describe, expect, it } from "vitest";
import { findServerActionEntries } from "./serverActions";

// Step 7E-1: which server actions the browser can call. An exported action is
// an entry when UI code imports it (a "use client" file or a .tsx component);
// "use server" helpers imported only by other server code are not entries.
const f = (path: string, content: string) => ({ path, content });

describe("findServerActionEntries", () => {
  it("finds actions imported by client or component files, by name", () => {
    const entries = findServerActionEntries([
      f("app/actions/survey.ts", '"use server";\nexport async function updateSurvey() {}\nexport const deleteSurvey = async () => {};\nexport async function unusedAction() {}'),
      f("components/SurveyForm.tsx", '"use client";\nimport { updateSurvey, deleteSurvey as remove } from "@/app/actions/survey";'),
      f("lib/helpers/enroll.ts", '"use server";\nexport async function enroll() {}'),
      f("app/actions/partner.ts", '"use server";\nimport { enroll } from "@/lib/helpers/enroll";\nexport async function addPartner() { await enroll(); }'),
      f("app/partners/page.tsx", 'import { addPartner } from "../actions/partner";\nexport default function P() { return <form action={addPartner} />; }'),
    ]);
    expect(entries).toEqual([
      { file: "app/actions/partner.ts", name: "addPartner", importedBy: ["app/partners/page.tsx"] },
      { file: "app/actions/survey.ts", name: "deleteSurvey", importedBy: ["components/SurveyForm.tsx"] },
      { file: "app/actions/survey.ts", name: "updateSurvey", importedBy: ["components/SurveyForm.tsx"] },
    ]);
  });

  it("does not count a helper imported only by server code or a route handler", () => {
    expect(findServerActionEntries([
      f("lib/helpers/enroll.ts", '"use server";\nexport async function enroll() {}'),
      f("app/api/x/route.ts", 'import { enroll } from "@/lib/helpers/enroll";\nexport async function POST() { await enroll(); }'),
      f("lib/jobs/run.ts", 'import { enroll } from "@/lib/helpers/enroll";'),
    ])).toEqual([]);
  });

  it("resolves monorepo aliases through tsconfig paths", () => {
    expect(findServerActionEntries([
      f("apps/web/tsconfig.json", '{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["./*"] } } }'),
      f("apps/web/lib/actions/rename.ts", '"use server";\nexport const renameLink = actionClient.action(async () => {});'),
      f("apps/web/ui/links/rename.tsx", '"use client";\nimport { renameLink } from "@/lib/actions/rename";'),
    ])).toEqual([{ file: "apps/web/lib/actions/rename.ts", name: "renameLink", importedBy: ["apps/web/ui/links/rename.tsx"] }]);
  });

  it("ignores node_modules and test files", () => {
    expect(findServerActionEntries([
      f("node_modules/x/a.ts", '"use server";\nexport async function a() {}'),
      f("app/a.test.tsx", 'import { a } from "../node_modules/x/a";'),
    ])).toEqual([]);
  });
});
