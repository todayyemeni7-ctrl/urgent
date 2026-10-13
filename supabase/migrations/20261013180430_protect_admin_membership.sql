-- Keep at least one admin and prevent accidental self-demotion.
create or replace function public.urgent_set_member(p_room uuid, p_email text, p_role text, p_display_name text)
returns uuid language plpgsql security definer
set search_path = ''
as $$
declare
  v_user uuid;
  v_current_role text;
  v_admin_count integer;
begin
  if not public.urgent_has_role(p_room, array['admin']) then
    raise exception 'not authorized' using errcode = '42501';
  end if;
  if p_role not in ('admin','editor','operator','reader') then
    raise exception 'invalid role' using errcode = '22023';
  end if;
  if p_email is null or length(trim(p_email)) > 320 then
    raise exception 'invalid email' using errcode = '22023';
  end if;
  select u.id into v_user from auth.users u where lower(u.email) = lower(trim(p_email)) limit 1;
  if v_user is null then
    raise exception 'auth user not found' using errcode = 'P0002';
  end if;
  select m.role into v_current_role from public.room_members m where m.room_id = p_room and m.user_id = v_user;
  if v_user = (select auth.uid()) and p_role <> 'admin' then
    raise exception 'cannot change own role' using errcode = '22023';
  end if;
  if v_current_role = 'admin' and p_role <> 'admin' then
    select count(*) into v_admin_count from public.room_members m where m.room_id = p_room and m.role = 'admin';
    if v_admin_count <= 1 then
      raise exception 'cannot demote last admin' using errcode = '22023';
    end if;
  end if;
  insert into public.room_members(room_id, user_id, role, display_name)
  values (p_room, v_user, p_role, coalesce(nullif(trim(p_display_name), ''), split_part(trim(p_email), '@', 1)))
  on conflict (room_id, user_id) do update
    set role = excluded.role, display_name = excluded.display_name;
  return v_user;
end;
$$;
revoke all on function public.urgent_set_member(uuid,text,text,text) from public, anon;
grant execute on function public.urgent_set_member(uuid,text,text,text) to authenticated;
