-- Allow authenticated members to publish short-lived broadcasts and presence state
-- only to their own private newsroom topic.
drop policy if exists urgent_room_broadcast_read on realtime.messages;
create policy urgent_room_realtime_read on realtime.messages
  for select to authenticated
  using (
    extension in ('broadcast','presence')
    and (select realtime.topic()) like 'urgent-room:%'
    and exists (
      select 1 from public.room_members m
       where m.user_id = (select auth.uid())
         and ('urgent-room:' || m.room_id::text) = (select realtime.topic())
    )
  );

create policy urgent_room_realtime_insert on realtime.messages
  for insert to authenticated
  with check (
    extension in ('broadcast','presence')
    and (select realtime.topic()) like 'urgent-room:%'
    and exists (
      select 1 from public.room_members m
       where m.user_id = (select auth.uid())
         and ('urgent-room:' || m.room_id::text) = (select realtime.topic())
    )
  );
