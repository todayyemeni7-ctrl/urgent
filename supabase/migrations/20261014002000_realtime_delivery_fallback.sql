-- Add a second, standard Postgres Changes path alongside the private broadcast
-- trigger. RLS on urgent_items remains the authority for row visibility.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_publication_tables
     WHERE pubname = 'supabase_realtime'
       AND schemaname = 'public'
       AND tablename = 'urgent_items'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.urgent_items;
  END IF;
END
$$;

-- Supports low-frequency recovery queries by room and last update time.
CREATE INDEX IF NOT EXISTS urgent_items_room_updated_idx
  ON public.urgent_items (room_id, updated_at);
