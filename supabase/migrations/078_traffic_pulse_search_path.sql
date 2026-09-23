-- Pin traffic_pulse's search_path (Supabase advisor 0011, function search
-- path mutable). Its body schema-qualifies every table and uses only built-in
-- functions, so pinning changes no result; it removes the chance that a caller
-- with a crafted search_path resolves an operator or function elsewhere.
alter function public.traffic_pulse(uuid, int, int) set search_path = pg_catalog, public;
