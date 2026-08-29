-- A fourth fact surface: live provider configuration, read through an API.
--
-- source is the repository, db is the database, traffic is what arrived at the
-- edge. runtime is what a provider says about itself right now: which
-- environment variables exist and where they are scoped, whether sign-up is
-- open, whether a webhook endpoint verifies signatures. None of it is in the
-- repository, and it is the half that turns an inferred finding into one we
-- watched happen.
--
-- The CHECK is the reason this migration exists. Three places must agree on
-- this list: here, Collector in lib/graph/graphRun.ts, and GraphCollector in
-- lib/monitoring/registry.ts. A collector writing a value this CHECK rejects
-- fails silently into saveFacts's fail-soft catch.

alter table public.graph_facts drop constraint if exists graph_facts_collector_check;

alter table public.graph_facts
  add constraint graph_facts_collector_check
  check (collector in ('source', 'db', 'traffic', 'runtime'));

comment on column public.graph_facts.collector is
  'Which surface produced these facts. runtime = live third-party provider config read through an API (hosting, auth, payments), as opposed to source (the repository) or db (the database).';
