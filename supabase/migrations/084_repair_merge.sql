-- Close the repair loop after a human merge (Step 8-R). When GitHub reports a
-- merged pull request, the receipt ShipLock opened for it is stamped
-- `merged_at` (the webhook then queues a recheck of the default branch).
-- Only an `opened` receipt of the same tenant, repository and PR number is
-- stamped, and only once. ShipLock never merges; this records the customer's
-- merge that GitHub reported through a signed webhook.
alter table public.repair_action_receipts add column merged_at timestamptz;
alter table public.repair_action_receipts
  add constraint repair_action_receipts_merged_only_opened check (merged_at is null or status = 'opened');

create function public.record_repair_merge(p_user uuid, p_repository uuid, p_pr integer)
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare stamped integer;
begin
  if p_pr is null or p_pr <= 0 then raise exception 'invalid pull request'; end if;
  update public.repair_action_receipts set merged_at = now(), updated_at = now()
    where user_id = p_user and repository_id = p_repository and pr_number = p_pr
      and status = 'opened' and merged_at is null;
  get diagnostics stamped = row_count;
  return stamped;
end $$;

revoke all on function public.record_repair_merge(uuid,uuid,integer) from public, anon, authenticated;
grant execute on function public.record_repair_merge(uuid,uuid,integer) to service_role;
