import { describe, expect, it } from "vitest";
import { AgentActionRefused, assertAgentAction, checkAgentAction, summariseAttempts } from "./agentGuard";

const S = "proving_abc";
const ok = (sql: string) => checkAgentAction(sql, S).allowed;

describe("what the agent may do", () => {
  it("permits a plain read inside the replica", () => {
    expect(ok(`select * from ${S}.invoices`)).toBe(true);
    expect(ok(`select count(*) from ${S}.invoices where user_id = '00000000-0000-4000-8000-00000000000b'`)).toBe(true);
  });

  it("permits a CTE and a join within the replica", () => {
    expect(ok(`with x as (select * from ${S}.invoices) select * from x`)).toBe(true);
    expect(ok(`select a.* from ${S}.invoices a join ${S}.orders b on a.id = b.id`)).toBe(true);
  });

  // A policy identifies the caller through auth.uid(), so an agent testing
  // policies must be able to reference it.
  it("permits auth.uid() as a function call", () => {
    expect(ok(`select * from ${S}.invoices where user_id = auth.uid()`)).toBe(true);
  });
});

describe("what the agent may NOT do", () => {
  it("refuses every write", () => {
    for (const sql of [
      `insert into ${S}.invoices (user_id) values ('x')`,
      `update ${S}.invoices set user_id = 'x'`,
      `delete from ${S}.invoices`,
      `drop table ${S}.invoices`,
      `alter table ${S}.invoices disable row level security`,
      `create policy p on ${S}.invoices for select using (true)`,
      `grant select on ${S}.invoices to anon`,
      `truncate ${S}.invoices`,
    ]) {
      expect(ok(sql), sql).toBe(false);
    }
  });

  // Disabling RLS would make every subsequent "leak" a fabrication.
  it("refuses to alter the very policies it is testing", () => {
    expect(ok(`alter table ${S}.invoices disable row level security`)).toBe(false);
    expect(ok(`drop policy p_0 on ${S}.invoices`)).toBe(false);
  });

  // The realistic failure: a capable model being helpful in a wrong direction.
  it("refuses reads of system and platform schemas", () => {
    for (const sql of [
      `select * from pg_catalog.pg_policies`,
      `select * from information_schema.columns`,
      `select * from auth.users`,
      `select * from storage.objects`,
      `select * from vault.secrets`,
    ]) {
      expect(ok(sql), sql).toBe(false);
    }
  });

  it("refuses another schema even when the replica is also referenced", () => {
    expect(ok(`select * from ${S}.invoices union all select id::text from public.user_profiles`)).toBe(false);
  });

  it("refuses functions that reach the filesystem, network or other databases", () => {
    for (const sql of [
      `select pg_read_file('/etc/passwd')`,
      `select * from dblink('host=x', 'select 1') as t(a text)`,
      `select net.http_get('https://evil.example')`,
      `select pg_sleep(60)`,
      `select set_config('role', 'postgres', false)`,
    ]) {
      expect(ok(sql), sql).toBe(false);
    }
  });

  it("refuses more than one statement", () => {
    expect(ok(`select 1 from ${S}.invoices; drop table ${S}.invoices`)).toBe(false);
  });

  // `select 1 -- ; drop table x` is a real trick.
  it("strips comments before judging, so a hidden statement cannot slip through", () => {
    expect(ok(`select * from ${S}.invoices -- ; drop table x`)).toBe(true);
    expect(ok(`select * from ${S}.invoices /* comment */ ; delete from ${S}.invoices`)).toBe(false);
  });

  // A literal containing a keyword must not be mistaken for that keyword.
  it("ignores keywords inside string literals", () => {
    expect(ok(`select * from ${S}.invoices where note = 'please update this'`)).toBe(true);
  });

  it("refuses session control", () => {
    expect(ok(`select * from ${S}.invoices where id in (select 1)`)).toBe(true);
    expect(ok(`set role postgres`)).toBe(false);
    expect(ok(`begin`)).toBe(false);
  });

  it("requires the replica schema to be named explicitly", () => {
    // Unqualified names resolve through search_path, which we do not control.
    expect(ok(`select * from invoices`)).toBe(false);
  });

  it("refuses an over-long statement", () => {
    expect(ok(`select * from ${S}.invoices where x = '${"a".repeat(2100)}'`)).toBe(false);
  });

  it("refuses empty or non-string input", () => {
    expect(ok("")).toBe(false);
    expect(ok("   ")).toBe(false);
    expect(checkAgentAction(null as unknown as string, S).allowed).toBe(false);
  });

  it("refuses when the proving schema itself is malformed", () => {
    expect(checkAgentAction("select 1 from x.y", 'bad"schema').allowed).toBe(false);
  });
});

describe("assertAgentAction", () => {
  it("throws a typed refusal", () => {
    expect(() => assertAgentAction(`drop table ${S}.invoices`, S)).toThrow(AgentActionRefused);
  });

  it("passes a permitted statement through", () => {
    expect(() => assertAgentAction(`select * from ${S}.invoices`, S)).not.toThrow();
  });
});

describe("evidence trail", () => {
  // "The agent tried to read auth.users and was refused" must be visible, not
  // swallowed.
  it("counts refusals separately from runs", () => {
    const s = summariseAttempts([
      { sql: "a", allowed: true, reason: "" },
      { sql: "b", allowed: false, reason: "system schema" },
      { sql: "c", allowed: false, reason: "write" },
    ]);
    expect(s).toContain("3 queries proposed");
    expect(s).toContain("1 run");
    expect(s).toContain("2 refused");
  });

  it("omits the refusal count when there were none", () => {
    expect(summariseAttempts([{ sql: "a", allowed: true, reason: "" }])).not.toContain("refused");
  });
});
