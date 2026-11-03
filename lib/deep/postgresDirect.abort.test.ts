import { beforeEach, describe, expect, it, vi } from "vitest";

// Pg's Client takes no AbortSignal, so cancellation must end the
// session itself. Closing the socket rejects the in-flight catalogue query.
const client = vi.hoisted(() => ({
  connect: vi.fn(), query: vi.fn(), end: vi.fn(),
}));
vi.mock("pg", () => ({ Client: vi.fn(function Client() { return client; }) }));

import { withReadOnlySession, parseConnectionString } from "./postgresDirect";

const connection = parseConnectionString("postgres://reader:secret@db.example.com/app");
const lookup = vi.fn(async () => ["93.184.216.34"]);
const publicResolver = { lookup };

beforeEach(() => {
  vi.clearAllMocks();
  client.connect.mockResolvedValue(undefined);
  client.end.mockResolvedValue(undefined);
  client.query.mockResolvedValue({ rows: [] });
});

describe("withReadOnlySession cancellation", () => {
  it("does not resolve or connect when the signal is already aborted", async () => {
    const controller = new AbortController();
    controller.abort(new Error("collector timed out"));
    await expect(withReadOnlySession(connection, async () => "unused", publicResolver, controller.signal))
      .rejects.toThrow("collector timed out");
    expect(lookup).not.toHaveBeenCalled();
    expect(client.connect).not.toHaveBeenCalled();
  });

  it("ends the session when aborted mid-query and rejects with the abort reason", async () => {
    const controller = new AbortController();
    let rejectQuery: (err: Error) => void = () => {};
    client.query.mockImplementation(async (sql: string) => {
      if (sql.startsWith("BEGIN")) return { rows: [] };
      return new Promise((_resolve, reject) => { rejectQuery = reject; });
    });
    client.end.mockImplementation(async () => { rejectQuery(new Error("Connection terminated")); });
    const run = withReadOnlySession(connection, (query) => query("SELECT 1"), publicResolver, controller.signal);
    await vi.waitFor(() => expect(client.query).toHaveBeenCalledWith("SELECT 1", undefined));
    controller.abort(new Error("collector timed out"));
    await expect(run).rejects.toThrow("collector timed out");
    expect(client.end).toHaveBeenCalled();
    expect(client.query).not.toHaveBeenCalledWith("COMMIT");
  });
});
