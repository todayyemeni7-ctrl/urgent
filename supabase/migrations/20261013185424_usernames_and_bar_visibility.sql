-- Username-based internal Auth aliases, per-member ticker visibility, and isolated bar Realtime.
-- No secret key or plaintext password is stored in this migration.

alter table public.room_members
  add column if not exists username text,
  add column if not exists can_view_bar boolean not null default true;

create unique index if not exists room_members_username_uidx
  on public.room_members (lower(username)) where username is not null;

create or replace function public.urgent_username_alias(p_username text)
returns text
language sql immutable strict
set search_path = ''
as $$
  select 'ua-' || pg_catalog.substr(
    pg_catalog.encode(
      extensions.digest(
        pg_catalog.convert_to(pg_catalog.lower(pg_catalog.btrim(p_username)), 'UTF8'),
        'sha256'
      ),
      'hex'
    ),
    1,
    40
  ) || '@login.urgent.invalid';
$$;
revoke all on function public.urgent_username_alias(text) from public, anon, authenticated;

create or replace function public.urgent_can_view_bar(p_room uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.room_members m
     where m.room_id = p_room
       and m.user_id = (select auth.uid())
       and m.can_view_bar
  );
$$;
revoke all on function public.urgent_can_view_bar(uuid) from public, anon;
grant execute on function public.urgent_can_view_bar(uuid) to authenticated;

-- Database reads are filtered, not just hidden by client-side presentation.
drop policy if exists items_member_read on public.urgent_items;
create policy items_member_read on public.urgent_items for select to authenticated
  using (
    public.urgent_is_member(room_id)
    and (kind <> 'bar' or public.urgent_can_view_bar(room_id))
  );

-- Private base channel carries non-bar rows and presence. Bar records live only
-- on a second private topic whose SELECT policy is limited to members with access.
drop policy if exists urgent_room_broadcast_read on realtime.messages;
drop policy if exists urgent_room_realtime_read on realtime.messages;
create policy urgent_room_realtime_read on realtime.messages
  for select to authenticated
  using (
    extension in ('broadcast','presence')
    and exists (
      select 1 from public.room_members m
       where m.user_id = (select auth.uid())
         and ('urgent-room:' || m.room_id::text) = (select realtime.topic())
    )
  );
create policy urgent_room_bars_read on realtime.messages
  for select to authenticated
  using (
    extension = 'broadcast'
    and exists (
      select 1 from public.room_members m
       where m.user_id = (select auth.uid())
         and m.can_view_bar
         and ('urgent-room:' || m.room_id::text || ':bars') = (select realtime.topic())
    )
  );

drop policy if exists urgent_room_realtime_insert on realtime.messages;
create policy urgent_room_realtime_insert on realtime.messages
  for insert to authenticated
  with check (
    (extension = 'presence'
      and exists (
        select 1 from public.room_members m
         where m.user_id = (select auth.uid())
           and ('urgent-room:' || m.room_id::text) = (select realtime.topic())
      ))
    or
    (extension = 'broadcast'
      and exists (
        select 1 from public.room_members m
         where m.user_id = (select auth.uid())
           and m.role in ('admin','editor')
           and (
             ('urgent-room:' || m.room_id::text) = (select realtime.topic())
             or (m.can_view_bar and ('urgent-room:' || m.room_id::text || ':bars') = (select realtime.topic()))
           )
      ))
  );

create or replace function public.urgent_broadcast_item_change()
returns trigger language plpgsql security definer
set search_path = ''
as $$
declare
  r uuid;
  k text;
  v_topic text;
begin
  r := coalesce(new.room_id, old.room_id);
  k := coalesce(new.kind, old.kind);
  v_topic := 'urgent-room:' || r::text || case when k = 'bar' then ':bars' else '' end;
  perform realtime.broadcast_changes(
    v_topic,
    tg_op,
    tg_op,
    tg_table_name,
    tg_table_schema,
    new,
    old
  );
  return null;
end;
$$;
revoke all on function public.urgent_broadcast_item_change() from public, anon, authenticated;

-- An item cannot change type after creation; this prevents moving a bar payload
-- from a protected channel to the general newsroom feed (or vice versa).
create or replace function public.urgent_save_item(
  p_room uuid,
  p_item_key text,
  p_kind text,
  p_content text,
  p_author text,
  p_created_ms bigint,
  p_edited_ms bigint
) returns void language plpgsql security definer
set search_path = ''
as $$
declare
  v_existing_kind text;
begin
  if not public.urgent_has_role(p_room, array['admin','editor']) then
    raise exception 'not authorized' using errcode = '42501';
  end if;
  if p_kind not in ('news','note','bar') or p_item_key is null or length(p_item_key) > 160 then
    raise exception 'invalid item' using errcode = '22023';
  end if;
  if p_kind = 'bar' and not public.urgent_can_view_bar(p_room) then
    raise exception 'bar visibility required' using errcode = '42501';
  end if;
  if p_content is null or length(p_content) = 0 or length(p_content) > 30000 then
    raise exception 'invalid content' using errcode = '22023';
  end if;
  select i.kind into v_existing_kind from public.urgent_items i
   where i.room_id = p_room and i.item_key = p_item_key for update;
  if found and v_existing_kind <> p_kind then
    raise exception 'item type cannot be changed' using errcode = '22023';
  end if;
  insert into public.urgent_items (room_id, item_key, kind, content, author, created_ms, edited_ms)
  values (p_room, p_item_key, p_kind, p_content, coalesce(p_author, ''), p_created_ms, p_edited_ms)
  on conflict (room_id, item_key) do update
    set content = excluded.content,
        author = excluded.author,
        created_ms = excluded.created_ms,
        edited_ms = excluded.edited_ms,
        deleted_at = null,
        updated_at = now();
end;
$$;
revoke all on function public.urgent_save_item(uuid,text,text,text,text,bigint,bigint) from public, anon;
grant execute on function public.urgent_save_item(uuid,text,text,text,text,bigint,bigint) to authenticated;

create or replace function public.urgent_ack_item(p_room uuid, p_item_key text, p_ack jsonb)
returns void language plpgsql security definer
set search_path = ''
as $$
begin
  if not public.urgent_has_role(p_room, array['admin','editor','operator']) then
    raise exception 'not authorized' using errcode = '42501';
  end if;
  if exists (
    select 1 from public.urgent_items i
     where i.room_id = p_room and i.item_key = p_item_key and i.kind = 'bar'
  ) and not public.urgent_can_view_bar(p_room) then
    raise exception 'bar visibility required' using errcode = '42501';
  end if;
  update public.urgent_items set ack = p_ack, updated_at = now()
   where room_id = p_room and item_key = p_item_key and deleted_at is null;
  if not found then raise exception 'item not found' using errcode = 'P0002'; end if;
end;
$$;
revoke all on function public.urgent_ack_item(uuid,text,jsonb) from public, anon;
grant execute on function public.urgent_ack_item(uuid,text,jsonb) to authenticated;

create or replace function public.urgent_pin_item(p_room uuid, p_item_key text, p_pin jsonb)
returns void language plpgsql security definer
set search_path = ''
as $$
begin
  if not public.urgent_has_role(p_room, array['admin','editor']) then
    raise exception 'not authorized' using errcode = '42501';
  end if;
  if exists (
    select 1 from public.urgent_items i
     where i.room_id = p_room and i.item_key = p_item_key and i.kind = 'bar'
  ) and not public.urgent_can_view_bar(p_room) then
    raise exception 'bar visibility required' using errcode = '42501';
  end if;
  update public.urgent_items set pin = p_pin, updated_at = now()
   where room_id = p_room and item_key = p_item_key and deleted_at is null;
  if not found then raise exception 'item not found' using errcode = 'P0002'; end if;
end;
$$;
revoke all on function public.urgent_pin_item(uuid,text,jsonb) from public, anon;
grant execute on function public.urgent_pin_item(uuid,text,jsonb) to authenticated;

-- Replace email-oriented member RPCs; email addresses are not returned to the UI.
drop function if exists public.urgent_list_members(uuid);
create function public.urgent_list_members(p_room uuid)
returns table(user_id uuid, username text, display_name text, role text, can_view_bar boolean)
language plpgsql stable security definer
set search_path = ''
as $$
begin
  if not public.urgent_has_role(p_room, array['admin']) then
    raise exception 'not authorized' using errcode = '42501';
  end if;
  return query
    select m.user_id, m.username, m.display_name, m.role, m.can_view_bar
      from public.room_members m
     where m.room_id = p_room
     order by m.role, m.display_name
     limit 100;
end;
$$;
revoke all on function public.urgent_list_members(uuid) from public, anon;
grant execute on function public.urgent_list_members(uuid) to authenticated;

drop function if exists public.urgent_set_member(uuid,text,text,text);
create function public.urgent_set_member(
  p_room uuid,
  p_username text,
  p_role text,
  p_display_name text,
  p_can_view_bar boolean,
  p_user uuid default null
) returns uuid language plpgsql security definer
set search_path = ''
as $$
declare
  v_user uuid;
  v_alias_user uuid;
  v_username text;
  v_email text;
  v_current_role text;
  v_current_name text;
  v_current_username text;
  v_has_membership boolean := false;
  v_admin_count integer;
  v_display_name text;
begin
  perform 1 from public.rooms r where r.id = p_room for update;
  if not found then raise exception 'room not found' using errcode = 'P0002'; end if;
  if not public.urgent_has_role(p_room, array['admin']) then
    raise exception 'not authorized' using errcode = '42501';
  end if;
  if p_role is null or p_role not in ('admin','editor','operator','reader') then
    raise exception 'invalid role' using errcode = '22023';
  end if;

  v_username := nullif(pg_catalog.lower(pg_catalog.btrim(coalesce(p_username, ''))), '');
  if v_username is not null and (
    pg_catalog.char_length(v_username) < 3 or pg_catalog.char_length(v_username) > 32
    or v_username ~ '[[:space:]@]'
  ) then
    raise exception 'invalid username' using errcode = '22023';
  end if;

  if p_user is not null then
    v_user := p_user;
    select m.role, m.display_name, m.username
      into v_current_role, v_current_name, v_current_username
      from public.room_members m where m.room_id = p_room and m.user_id = v_user;
    v_has_membership := found;
    if v_username is not null then
      v_email := public.urgent_username_alias(v_username);
      select u.id into v_alias_user from auth.users u where pg_catalog.lower(u.email) = v_email limit 1;
      if v_alias_user is distinct from v_user then
        raise exception 'username does not match auth user' using errcode = '22023';
      end if;
    elsif not v_has_membership then
      raise exception 'member not found' using errcode = 'P0002';
    end if;
  else
    if v_username is null then raise exception 'username required' using errcode = '22023'; end if;
    v_email := public.urgent_username_alias(v_username);
    select u.id into v_user from auth.users u where pg_catalog.lower(u.email) = v_email limit 1;
    if v_user is null then raise exception 'auth user not found' using errcode = 'P0002'; end if;
    select m.role, m.display_name, m.username
      into v_current_role, v_current_name, v_current_username
      from public.room_members m where m.room_id = p_room and m.user_id = v_user;
    v_has_membership := found;
  end if;

  if v_user = (select auth.uid()) and p_role <> 'admin' then
    raise exception 'cannot change own role' using errcode = '22023';
  end if;
  if v_current_role = 'admin' and p_role <> 'admin' then
    select count(*) into v_admin_count from public.room_members m
     where m.room_id = p_room and m.role = 'admin';
    if v_admin_count <= 1 then raise exception 'cannot demote last admin' using errcode = '22023'; end if;
  end if;

  v_display_name := coalesce(
    nullif(pg_catalog.btrim(coalesce(p_display_name, '')), ''),
    nullif(v_current_name, ''),
    v_username,
    'عضو'
  );
  if pg_catalog.char_length(v_display_name) > 80 then
    raise exception 'display name too long' using errcode = '22023';
  end if;

  insert into public.room_members(room_id, user_id, username, role, display_name, can_view_bar)
  values (p_room, v_user, coalesce(v_username, v_current_username), p_role, v_display_name, coalesce(p_can_view_bar, false))
  on conflict (room_id, user_id) do update
    set username = coalesce(excluded.username, room_members.username),
        role = excluded.role,
        display_name = excluded.display_name,
        can_view_bar = excluded.can_view_bar;
  return v_user;
end;
$$;
revoke all on function public.urgent_set_member(uuid,text,text,text,boolean,uuid) from public, anon;
grant execute on function public.urgent_set_member(uuid,text,text,text,boolean,uuid) to authenticated;
