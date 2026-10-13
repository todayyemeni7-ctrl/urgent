-- Presence is available to all authenticated room members. General client broadcasts
-- are limited to admins and editors; durable newsroom content remains in Postgres.
drop policy if exists urgent_room_realtime_insert on realtime.messages;
create policy urgent_room_realtime_insert on realtime.messages
  for insert to authenticated
  with check (
    (extension = 'presence'
      and (select realtime.topic()) like 'urgent-room:%'
      and exists (
        select 1 from public.room_members m
         where m.user_id = (select auth.uid())
           and ('urgent-room:' || m.room_id::text) = (select realtime.topic())
      ))
    or
    (extension = 'broadcast'
      and (select realtime.topic()) like 'urgent-room:%'
      and exists (
        select 1 from public.room_members m
         where m.user_id = (select auth.uid())
           and m.role in ('admin','editor')
           and ('urgent-room:' || m.room_id::text) = (select realtime.topic())
      ))
  );
