-- One round-trip for publishing/editing while preserving acknowledgement and pin state.
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
begin
  if not public.urgent_has_role(p_room, array['admin','editor']) then
    raise exception 'not authorized' using errcode = '42501';
  end if;
  if p_kind not in ('news','note','bar') or p_item_key is null or length(p_item_key) > 160 then
    raise exception 'invalid item' using errcode = '22023';
  end if;
  if p_content is null or length(p_content) = 0 or length(p_content) > 30000 then
    raise exception 'invalid content' using errcode = '22023';
  end if;
  insert into public.urgent_items (room_id, item_key, kind, content, author, created_ms, edited_ms)
  values (p_room, p_item_key, p_kind, p_content, coalesce(p_author, ''), p_created_ms, p_edited_ms)
  on conflict (room_id, item_key) do update
    set kind = excluded.kind,
        content = excluded.content,
        author = excluded.author,
        created_ms = excluded.created_ms,
        edited_ms = excluded.edited_ms,
        deleted_at = null,
        updated_at = now();
end;
$$;
revoke all on function public.urgent_save_item(uuid,text,text,text,text,bigint,bigint) from public, anon;
grant execute on function public.urgent_save_item(uuid,text,text,text,text,bigint,bigint) to authenticated;
