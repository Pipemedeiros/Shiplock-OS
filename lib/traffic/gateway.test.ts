import { describe, expect, it } from "vitest";
import { gatewayLabel } from "./gateway";

// What a Supabase gateway path is, in a founder's words.
describe("gatewayLabel", () => {
  it("names the table, function, bucket or service a path reaches", () => {
    expect(gatewayLabel("/rest/v1/orders")).toBe("Table orders");
    expect(gatewayLabel("/rest/v1/rpc/get_invoices")).toBe("Database function get_invoices");
    expect(gatewayLabel("/storage/v1/object/public/avatars/a.png")).toBe("Storage bucket avatars");
    expect(gatewayLabel("/storage/v1/object/list/docs")).toBe("Storage bucket docs");
    expect(gatewayLabel("/auth/v1/token")).toBe("Sign in");
    expect(gatewayLabel("/functions/v1/send-email")).toBe("Edge function send-email");
    expect(gatewayLabel("/graphql/v1")).toBe("GraphQL");
    expect(gatewayLabel("/realtime/v1/websocket")).toBe("/realtime/v1/websocket");
  });
});
