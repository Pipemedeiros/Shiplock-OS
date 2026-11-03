import { describe, expect, it } from "vitest";
import { findServerActionEntries } from "./serverActions";

// Which server actions the browser can call. An exported action is
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

  // A batched corpus run (2026-10-09): a server component that only AWAITS an action
  // on the server never sends its id to the browser, so anyone cannot call
  // it. It exposes the action only by handing it over: a form or button
  // action, or a prop to a client component.
  it("does not count a server component that only calls the action on the server", () => {
    const action = f("actions/contact.actions.ts", '"use server";\nexport async function getContactById(id) { return db.contact.find(id); }');
    expect(findServerActionEntries([action,
      f("app/dashboard/contact/[id]/page.tsx", 'import { getContactById } from "@/actions/contact.actions";\nexport default async function P({ params }) { const c = await getContactById(params.id); return <div>{c.name}</div>; }'),
    ])).toEqual([]);
    for (const use of ["<form action={getContactById} />", "<button formAction={getContactById} />", "<ContactView load={getContactById} />",
      "<Plan api={{ load: getContactById }} />", "<Plan api={{ getContactById }} />", "<Plan list={[getContactById]} />"]) {
      expect(findServerActionEntries([action,
        f("app/contact/page.tsx", `import { getContactById } from "@/actions/contact.actions";\nexport default function P() { return ${use}; }`),
      ]).map((e) => e.name)).toEqual(["getContactById"]);
    }
    // A component file without "use client" inherits the client boundary of
    // whatever imports it (corpus-a's ui/modals/*.tsx call actions from hooks):
    // only App Router page and layout files are known server components.
    expect(findServerActionEntries([action,
      f("ui/modals/contact-modal.tsx", 'import { getContactById } from "@/actions/contact.actions";\nexport function M() { const { execute } = useAction(getContactById); return null; }'),
    ]).map((e) => e.name)).toEqual(["getContactById"]);
    // A client component counts however it uses the action.
    expect(findServerActionEntries([action,
      f("components/Contact.tsx", '"use client";\nimport { getContactById } from "@/actions/contact.actions";\nexport function C() { getContactById(1); return null; }'),
    ]).map((e) => e.name)).toEqual(["getContactById"]);
  });

  // R2b (release attempt 3, 2026-10-13): corpus-z's sidebar component, a
  // server component outside app/ (no "use client", imported only by a
  // layout), awaited three actions on the server; they were reported as
  // callable by anyone. A component file is client only when a client root
  // reaches it: a "use client" file or a Pages Router page, through imports.
  it("does not count a server component outside app/ that only calls the action", () => {
    const action = f("src/lib/supabase/queries.ts", '"use server";\nexport async function getFolders(id) { return db.folders.find(id); }');
    const sidebar = f("src/components/sidebar/sidebar.tsx", 'import { getFolders } from "@/lib/supabase/queries";\nexport default async function Sidebar({ id }) { const f = await getFolders(id); return <nav>{f.length}</nav>; }');
    const layout = f("src/app/dashboard/layout.tsx", 'import Sidebar from "@/components/sidebar/sidebar";\nexport default function L({ children }) { return <Sidebar id="x" />; }');
    expect(findServerActionEntries([action, sidebar, layout])).toEqual([]);
    // A client root that reaches the component, directly or through another
    // component, puts it in the browser bundle.
    const shell = f("src/components/shell.tsx", '"use client";\nimport Frame from "./frame";\nexport function S() { return <Frame />; }');
    const frame = f("src/components/frame.tsx", 'import Sidebar from "./sidebar/sidebar";\nexport default function Frame() { return <Sidebar id="x" />; }');
    expect(findServerActionEntries([action, sidebar, layout, shell, frame]).map((e) => e.name)).toEqual(["getFolders"]);
    const page = f("src/pages/index.tsx", 'import Sidebar from "@/components/sidebar/sidebar";\nexport default function P() { return <Sidebar id="x" />; }');
    expect(findServerActionEntries([action, sidebar, page]).map((e) => e.name)).toEqual(["getFolders"]);
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

  // R2: an inline "use server" inside a function body marks that function,
  // not the file. A page with one is still a page that can hand an imported
  // action to the browser, and its own exports are not actions.
  it("reads a page with an inline server action as a page, not an actions module", () => {
    const entries = findServerActionEntries([
      f("app/actions/notes.ts", '"use server";\nexport async function deleteNote(id) {}'),
      f("app/notes/page.tsx", 'import { deleteNote } from "../actions/notes";\nexport const dynamic = "force-dynamic";\nexport default function Page() {\n  async function rename(form) {\n    "use server";\n    await db.note.update(form);\n  }\n  return <form action={deleteNote}><button formAction={rename} /></form>;\n}'),
      f("components/Panel.tsx", '"use client";\nimport { dynamic } from "@/app/notes/page";'),
    ]);
    expect(entries).toEqual([{ file: "app/actions/notes.ts", name: "deleteNote", importedBy: ["app/notes/page.tsx"] }]);
  });

  it("still reads a module directive after a leading comment", () => {
    const entries = findServerActionEntries([
      f("app/actions/a.ts", '// Server actions for notes.\n/* shared */\n"use server";\nexport async function save() {}'),
      f("components/A.tsx", '"use client";\nimport { save } from "@/app/actions/a";'),
    ]);
    expect(entries).toEqual([{ file: "app/actions/a.ts", name: "save", importedBy: ["components/A.tsx"] }]);
  });
});

