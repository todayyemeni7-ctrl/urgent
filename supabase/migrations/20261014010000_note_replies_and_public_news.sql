-- ردود المنفذ على الملاحظات + قراءة عامة للأخبار العاجلة فقط (الصفحة العامة)

-- 1) حقل الرد يُحفظ مع الخبر وينتقل عبر القنوات والمزامنة الموجودة
alter table public.urgent_items
  add column if not exists reply jsonb;

-- 2) حفظ الرد عبر RPC محمي بالدور — على نمط الإقرار والتثبيت تماماً
create or replace function public.urgent_reply_item(
  p_room uuid, p_item_key text, p_reply jsonb
) returns void language plpgsql security definer
set search_path = ''
as $$
begin
  if not public.urgent_has_role(p_room, array['admin','editor','operator']) then
    raise exception 'not authorized' using errcode = '42501';
  end if;
  update public.urgent_items
     set reply = p_reply, updated_at = now()
   where room_id = p_room and item_key = p_item_key and deleted_at is null;
  if not found then raise exception 'item not found' using errcode = 'P0002'; end if;
end;
$$;
revoke all on function public.urgent_reply_item(uuid,text,jsonb) from public, anon;
grant execute on function public.urgent_reply_item(uuid,text,jsonb) to authenticated;

-- 3) الصفحة العامة: أحدث الأخبار العاجلة فقط — دالة قراءة حكراً على kind='news'
--    لا تعيد ملاحظات ولا أشرطة ولا بيانات إقرار/نسخ، ولا تتطلب جلسة.
create or replace function public.urgent_public_news(
  p_room uuid, p_after_ms bigint default 0, p_limit integer default 200
) returns table(item_key text, content text, author text, created_ms bigint, edited_ms bigint)
language sql security definer stable
set search_path = ''
as $$
  select i.item_key, i.content, i.author, i.created_ms, i.edited_ms
  from public.urgent_items i
  where i.room_id = p_room
    and i.kind = 'news'
    and i.deleted_at is null
    and (p_after_ms is null or p_after_ms <= 0 or i.created_ms > p_after_ms)
  order by i.created_ms desc
  limit least(greatest(coalesce(p_limit, 200), 1), 500);
$$;
revoke all on function public.urgent_public_news(uuid,bigint,integer) from public;
grant execute on function public.urgent_public_news(uuid,bigint,integer) to anon, authenticated;
