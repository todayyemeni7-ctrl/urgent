-- Reader accounts may read news only. Notes and ticker rows remain available
-- only to the operational roles; bars also require the explicit visibility flag.
DROP POLICY IF EXISTS items_member_read ON public.urgent_items;
CREATE POLICY items_member_read ON public.urgent_items FOR SELECT TO authenticated
  USING (
    public.urgent_is_member(room_id)
    AND kind IN ('news', 'note', 'bar')
    AND (
      kind = 'news'
      OR public.urgent_has_role(room_id, ARRAY['admin','editor','operator'])
    )
    AND (
      kind <> 'bar'
      OR (
        public.urgent_has_role(room_id, ARRAY['admin','editor','operator'])
        AND public.urgent_can_view_bar(room_id)
      )
    )
  );

-- Readers keep Presence on the base topic but cannot receive general Broadcast
-- payloads, which include operational note/ack details. News still arrives via
-- RLS-filtered Postgres Changes and the existing incremental database sync.
DROP POLICY IF EXISTS urgent_room_realtime_read ON realtime.messages;
CREATE POLICY urgent_room_realtime_read ON realtime.messages
  FOR SELECT TO authenticated
  USING (
    (
      extension = 'presence'
      AND EXISTS (
        SELECT 1 FROM public.room_members m
         WHERE m.user_id = (SELECT auth.uid())
           AND ('urgent-room:' || m.room_id::text) = (SELECT realtime.topic())
      )
    )
    OR
    (
      extension = 'broadcast'
      AND EXISTS (
        SELECT 1 FROM public.room_members m
         WHERE m.user_id = (SELECT auth.uid())
           AND m.role IN ('admin','editor','operator')
           AND ('urgent-room:' || m.room_id::text) = (SELECT realtime.topic())
      )
    )
  );

DROP POLICY IF EXISTS urgent_room_bars_read ON realtime.messages;
CREATE POLICY urgent_room_bars_read ON realtime.messages
  FOR SELECT TO authenticated
  USING (
    extension = 'broadcast'
    AND EXISTS (
      SELECT 1 FROM public.room_members m
       WHERE m.user_id = (SELECT auth.uid())
         AND m.role IN ('admin','editor','operator')
         AND m.can_view_bar
         AND ('urgent-room:' || m.room_id::text || ':bars') = (SELECT realtime.topic())
    )
  );
