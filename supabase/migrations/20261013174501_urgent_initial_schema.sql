-- Yemen Today / Urgent: first durable data model.
-- Apply after creating a Supabase project. No service-role key is used by the app.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.rooms (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique,
  title text not null default 'غرفة الأخبار',
  created_at timestamptz not null default now()
);

create table if not exists public.room_members (
  room_id uuid not null references public.rooms(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('admin','editor','operator','reader')),
  display_name text not null default '',
  created_at timestamptz not null default now(),
  primary key (room_id, user_id)
);
create index if not exists room_members_user_room_idx on public.room_members(user_id, room_id);

create table if not exists public.urgent_items (
  id uuid primary key default gen_random_uuid(),
  room_id uuid not null references public.rooms(id) on delete cascade,
  item_key text not null,
  kind text not null check (kind in ('news','note','bar')),
  content text not null,
  author text not null default '',
  created_ms bigint not null,
  edited_ms bigint,
  ack jsonb,
  pin jsonb,
  deleted_at timestamptz,
  updated_at timestamptz not null default now(),
  unique(room_id, item_key)
);
create index if not exists urgent_items_room_created_idx on public.urgent_items(room_id, created_ms desc) where deleted_at is null;

-- Public-schema tables are locked down explicitly. RLS is defense in depth, not a
-- substitute for grants; the anon role receives no access to operational records.
alter table public.rooms enable row level security;
alter table public.room_members enable row level security;
alter table public.urgent_items enable row level security;
revoke all on public.rooms, public.room_members, public.urgent_items from anon, authenticated;
grant select on public.rooms, public.room_members, public.urgent_items to authenticated;
grant insert, update on public.urgent_items to authenticated;
grant delete on public.urgent_items to authenticated;

create or replace function public.urgent_is_member(p_room uuid)
returns boolean language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.room_members m
    where m.room_id = p_room and m.user_id = (select auth.uid())
  );
$$;
revoke all on function public.urgent_is_member(uuid) from public;
grant execute on function public.urgent_is_member(uuid) to authenticated;

create or replace function public.urgent_has_role(p_room uuid, p_roles text[])
returns boolean language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.room_members m
    where m.room_id = p_room and m.user_id = (select auth.uid()) and m.role = any(p_roles)
  );
$$;
revoke all on function public.urgent_has_role(uuid,text[]) from public;
grant execute on function public.urgent_has_role(uuid,text[]) to authenticated;

create policy rooms_member_read on public.rooms for select to authenticated
  using (public.urgent_is_member(id));
create policy room_members_self_or_admin_read on public.room_members for select to authenticated
  using (user_id = (select auth.uid()) or public.urgent_has_role(room_id, array['admin']));
create policy items_member_read on public.urgent_items for select to authenticated
  using (public.urgent_is_member(room_id));
create policy items_editor_insert on public.urgent_items for insert to authenticated
  with check (public.urgent_has_role(room_id, array['admin','editor']));
create policy items_editor_update on public.urgent_items for update to authenticated
  using (public.urgent_has_role(room_id, array['admin','editor']))
  with check (public.urgent_has_role(room_id, array['admin','editor']));
create policy items_admin_delete on public.urgent_items for delete to authenticated
  using (public.urgent_has_role(room_id, array['admin']));

-- Operators acknowledge/receive items through this narrow RPC rather than being
-- granted general UPDATE access to editorial content.
create or replace function public.urgent_ack_item(
  p_room uuid, p_item_key text, p_ack jsonb
) returns void language plpgsql security definer
set search_path = ''
as $$
begin
  if not public.urgent_has_role(p_room, array['admin','editor','operator']) then
    raise exception 'not authorized' using errcode = '42501';
  end if;
  update public.urgent_items
     set ack = p_ack, updated_at = now()
   where room_id = p_room and item_key = p_item_key and deleted_at is null;
  if not found then raise exception 'item not found' using errcode = 'P0002'; end if;
end;
$$;
revoke all on function public.urgent_ack_item(uuid,text,jsonb) from public, anon;
grant execute on function public.urgent_ack_item(uuid,text,jsonb) to authenticated;

-- Editors may pin, operators may not. Admins may manage room membership through
-- the Supabase Dashboard until an audited in-app member-management UI is added.
create or replace function public.urgent_pin_item(
  p_room uuid, p_item_key text, p_pin jsonb
) returns void language plpgsql security definer
set search_path = ''
as $$
begin
  if not public.urgent_has_role(p_room, array['admin','editor']) then
    raise exception 'not authorized' using errcode = '42501';
  end if;
  update public.urgent_items set pin = p_pin, updated_at = now()
   where room_id = p_room and item_key = p_item_key and deleted_at is null;
  if not found then raise exception 'item not found' using errcode = 'P0002'; end if;
end;
$$;
revoke all on function public.urgent_pin_item(uuid,text,jsonb) from public, anon;
grant execute on function public.urgent_pin_item(uuid,text,jsonb) to authenticated;

-- Private, room-scoped Realtime Broadcast. Database writes are the source of
-- truth; clients subscribe only to rooms in which their user has membership.
create policy urgent_room_broadcast_read on realtime.messages
  for select to authenticated
  using (
    extension = 'broadcast'
    and (select realtime.topic()) like 'urgent-room:%'
    and exists (
      select 1 from public.room_members m
       where m.user_id = (select auth.uid())
         and ('urgent-room:' || m.room_id::text) = (select realtime.topic())
    )
  );

create or replace function public.urgent_broadcast_item_change()
returns trigger language plpgsql security definer
set search_path = ''
as $$
declare
  r uuid;
begin
  r := coalesce(new.room_id, old.room_id);
  perform realtime.broadcast_changes(
    'urgent-room:' || r::text,
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

drop trigger if exists urgent_items_broadcast on public.urgent_items;
create trigger urgent_items_broadcast
  after insert or update or delete on public.urgent_items
  for each row execute function public.urgent_broadcast_item_change();

-- Enable Realtime for durable change feeds (private room channels still require
-- the realtime.messages authorization policy above).
alter table public.urgent_items replica identity full;
