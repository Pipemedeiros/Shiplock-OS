import { describe, expect, it } from "vitest";
import { isWorkflowFile, scanWorkflows, triggerNames } from "./workflowScan";

const wf = (content: string, path = ".github/workflows/ci.yml") => [{ path, content }];

describe("scope", () => {
  it("recognises workflow files", () => {
    expect(isWorkflowFile(".github/workflows/ci.yml")).toBe(true);
    expect(isWorkflowFile(".github/workflows/deploy.yaml")).toBe(true);
  });

  it("ignores other yaml", () => {
    expect(isWorkflowFile("docker-compose.yml")).toBe(false);
    expect(isWorkflowFile(".github/dependabot.yml")).toBe(false);
    expect(isWorkflowFile(".github/workflows/nested/x.yml")).toBe(false);
  });

  it("reads triggers in every YAML form", () => {
    expect(triggerNames("push")).toEqual(["push"]);
    expect(triggerNames(["push", "pull_request"])).toEqual(["push", "pull_request"]);
    expect(triggerNames({ push: null, schedule: [] })).toEqual(["push", "schedule"]);
    expect(triggerNames(undefined)).toEqual([]);
  });

  // Unknown is never a finding.
  it("says nothing about a workflow it cannot parse", () => {
    expect(scanWorkflows(wf("this: is: not: valid: yaml: [["))).toEqual([]);
  });
});

describe("pull_request_target RCE", () => {
  const vulnerable = `
name: pr
on: pull_request_target
jobs:
  build:
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test
`;

  it("flags checking out the PR head under pull_request_target", () => {
    const out = scanWorkflows(wf(vulnerable));
    const finding = out.find((x) => x.id.includes("prtarget_rce"))!;
    expect(finding.severity).toBe("CRITICAL");
    expect(finding.consequence).toContain("do not need it merged");
  });

  // pull_request_target alone is fine — that is what it is for.
  it("does NOT flag pull_request_target without a PR-head checkout", () => {
    const safe = `
on: pull_request_target
jobs:
  label:
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@v4
      - run: echo hi
`;
    expect(scanWorkflows(wf(safe)).filter((x) => x.id.includes("prtarget_rce"))).toEqual([]);
  });

  it("does not flag a normal pull_request workflow that checks out the head", () => {
    const safe = `
on: pull_request
jobs:
  build:
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@v4
        with: { ref: \${{ github.event.pull_request.head.sha }} }
`;
    expect(scanWorkflows(wf(safe)).filter((x) => x.id.includes("prtarget_rce"))).toEqual([]);
  });
});

describe("script injection", () => {
  it("flags an untrusted expression inside run:", () => {
    const bad = `
on: pull_request
jobs:
  x:
    permissions: { contents: read }
    steps:
      - run: echo "PR title is \${{ github.event.pull_request.title }}"
`;
    const out = scanWorkflows(wf(bad)).find((x) => x.id.includes("script_injection"))!;
    expect(out.severity).toBe("CRITICAL");
    expect(out.consequence).toContain("pass the value through the environment");
  });

  // THE reason this uses a parser: the same expression in `with:` is a
  // parameter, not a shell command.
  it("does NOT flag the same expression in a with: value", () => {
    const safe = `
on: pull_request
jobs:
  x:
    permissions: { contents: read }
    steps:
      - uses: some/action@0000000000000000000000000000000000000000
        with: { title: \${{ github.event.pull_request.title }} }
`;
    expect(scanWorkflows(wf(safe)).filter((x) => x.id.includes("script_injection"))).toEqual([]);
  });

  it("does not flag trusted contexts in run:", () => {
    const safe = `
on: push
jobs:
  x:
    permissions: { contents: read }
    steps:
      - run: echo "\${{ github.sha }} \${{ secrets.TOKEN }} \${{ github.repository }}"
`;
    expect(scanWorkflows(wf(safe)).filter((x) => x.id.includes("script_injection"))).toEqual([]);
  });
});

describe("unpinned actions", () => {
  it("flags a third-party action on a tag", () => {
    const bad = `
on: push
jobs:
  x:
    permissions: { contents: read }
    steps:
      - uses: some-vendor/deploy-action@v3
`;
    const out = scanWorkflows(wf(bad)).find((x) => x.id.includes("unpinned_action"))!;
    expect(out.severity).toBe("WARNING");
    expect(out.consequence).toContain("supply-chain");
  });

  it("accepts a SHA-pinned third-party action", () => {
    const good = `
on: push
jobs:
  x:
    permissions: { contents: read }
    steps:
      - uses: some-vendor/deploy-action@1234567890abcdef1234567890abcdef12345678
`;
    expect(scanWorkflows(wf(good)).filter((x) => x.id.includes("unpinned_action"))).toEqual([]);
  });

  // GitHub's own actions are conventionally tag-pinned; flagging them is noise.
  it("does not flag first-party actions/*", () => {
    const ok = `
on: push
jobs:
  x:
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
`;
    expect(scanWorkflows(wf(ok)).filter((x) => x.id.includes("unpinned_action"))).toEqual([]);
  });

  it("ignores local and docker actions", () => {
    const ok = `
on: push
jobs:
  x:
    permissions: { contents: read }
    steps:
      - uses: ./.github/actions/local
      - uses: docker://alpine:3
`;
    expect(scanWorkflows(wf(ok)).filter((x) => x.id.includes("unpinned_action"))).toEqual([]);
  });
});

describe("permissions", () => {
  it("notes a workflow with no permissions block", () => {
    const out = scanWorkflows(wf(`on: push\njobs:\n  x:\n    steps:\n      - run: echo hi\n`));
    const perm = out.find((x) => x.id.includes("no_permissions"))!;
    expect(perm.severity).toBe("INFO");
    // We cannot tell the repo default from the file, and say so.
    expect(perm.consequence).toContain("cannot tell which from the file alone");
  });

  it("is silent when declared at workflow level", () => {
    const ok = `on: push\npermissions: { contents: read }\njobs:\n  x:\n    steps:\n      - run: echo hi\n`;
    expect(scanWorkflows(wf(ok)).filter((x) => x.id.includes("no_permissions"))).toEqual([]);
  });

  it("is silent when every job declares its own", () => {
    const ok = `on: push\njobs:\n  x:\n    permissions: { contents: read }\n    steps:\n      - run: echo hi\n`;
    expect(scanWorkflows(wf(ok)).filter((x) => x.id.includes("no_permissions"))).toEqual([]);
  });
});

describe("aggregate", () => {
  it("is silent on a well-built workflow", () => {
    const good = `
name: ci
on: push
permissions:
  contents: read
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`;
    expect(scanWorkflows(wf(good))).toEqual([]);
  });

  it("ignores non-workflow files entirely", () => {
    expect(scanWorkflows([{ path: "lib/x.ts", content: "on: pull_request_target" }])).toEqual([]);
  });

  it("handles an empty file list", () => {
    expect(scanWorkflows([])).toEqual([]);
  });

  it("produces stable ids per file", () => {
    const bad = `on: push\njobs:\n  x:\n    steps:\n      - run: echo hi\n`;
    expect(scanWorkflows(wf(bad)).map((x) => x.id)).toEqual(scanWorkflows(wf(bad)).map((x) => x.id));
  });
});
