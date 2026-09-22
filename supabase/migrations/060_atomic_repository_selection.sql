-- Replace one customer's selected GitHub repository set in one transaction.
-- The API obtains this metadata from the current installation immediately
-- before calling the RPC; arbitrary client names never reach this function.
create function public.replace_selected_repositories(p_user uuid, p_repositories jsonb)
returns table(id uuid, full_name text)
language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  if p_repositories is null or jsonb_typeof(p_repositories) <> 'array'
    or jsonb_array_length(p_repositories) > 50 then
    raise exception 'invalid repository selection';
  end if;

  if exists (
    select 1
    from jsonb_to_recordset(p_repositories) as x(
      full_name text, github_repo_id text, default_branch text, private boolean
    )
    where x.full_name is null
      or x.full_name !~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'
      or x.default_branch is null or length(x.default_branch) not between 1 and 255
      or (x.github_repo_id is not null and x.github_repo_id !~ '^[1-9][0-9]*$')
  ) then raise exception 'invalid repository metadata'; end if;

  if (
    select count(*) <> count(distinct x.full_name)
    from jsonb_to_recordset(p_repositories) as x(full_name text)
  ) then raise exception 'duplicate repository'; end if;

  perform pg_advisory_xact_lock(hashtextextended(p_user::text,73610424));

  update public.repositories r set selected=false where r.user_id=p_user and r.selected=true;

  insert into public.repositories(
    user_id, full_name, github_repo_id, default_branch, private, selected
  )
  select p_user, x.full_name, x.github_repo_id::bigint, x.default_branch,
    coalesce(x.private,true), true
  from jsonb_to_recordset(p_repositories) as x(
    full_name text, github_repo_id text, default_branch text, private boolean
  )
  on conflict on constraint repositories_user_id_full_name_key do update set
    github_repo_id=excluded.github_repo_id,
    default_branch=excluded.default_branch,
    private=excluded.private,
    selected=true;

  return query select r.id,r.full_name from public.repositories r
    where r.user_id=p_user and r.selected=true order by r.full_name;
end $$;

revoke all on function public.replace_selected_repositories(uuid,jsonb)
  from public,anon,authenticated;
grant execute on function public.replace_selected_repositories(uuid,jsonb)
  to service_role;
