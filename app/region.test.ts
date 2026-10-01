import { readFileSync } from "node:fs";
import { expect, it } from "vitest";

// Felipe (2026-10-01): the dashboard felt slow. The database is in Supabase
// us-west-2 (Oregon) and functions ran in Vercel iad1 (Virginia): every
// sequential database call crossed the country (about 70 ms each, several per
// page). Functions run next to the database.
it("runs server functions in the database's region", () => {
  const config = JSON.parse(readFileSync("vercel.json", "utf8"));
  expect(config.regions).toEqual(["pdx1"]);
  expect(config.fluid).toBe(true);
});
