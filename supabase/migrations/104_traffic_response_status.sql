-- How the customer's app answered a mirrored request (Felipe 2026-10-16: see
-- the routes that were probably compromised). The snippet saw a request
-- before the app answered, so traffic could show attempts only. Snippets that
-- see the response (Express, the Web-standard wrapper) now send its status
-- code: one number, never a body or a header. Null means not reported (the
-- Next.js proxy runs before the route and cannot see it, and older snippets
-- send none); null is never read as success or refusal.
alter table public.traffic_events
  add column status smallint check (status between 100 and 599);
