-- Prevent a delayed automatic receive acknowledgment from downgrading a
-- stronger copy/receipt acknowledgment. The row lock serializes concurrent RPCs.
CREATE OR REPLACE FUNCTION public.urgent_ack_item(
  p_room uuid,
  p_item_key text,
  p_ack jsonb
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_current_ack jsonb;
BEGIN
  IF NOT public.urgent_has_role(p_room, ARRAY['admin','editor','operator']) THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.urgent_items i
     WHERE i.room_id = p_room AND i.item_key = p_item_key AND i.kind = 'bar'
  ) AND NOT public.urgent_can_view_bar(p_room) THEN
    RAISE EXCEPTION 'bar visibility required' USING errcode = '42501';
  END IF;

  SELECT i.ack INTO v_current_ack
    FROM public.urgent_items i
   WHERE i.room_id = p_room AND i.item_key = p_item_key AND i.deleted_at IS NULL
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'item not found' USING errcode = 'P0002';
  END IF;

  IF p_ack ->> 'k' = 'received'
     AND coalesce(v_current_ack ->> 'k', '') IN ('copied', 'got') THEN
    RETURN;
  END IF;

  UPDATE public.urgent_items
     SET ack = p_ack, updated_at = now()
   WHERE room_id = p_room AND item_key = p_item_key AND deleted_at IS NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.urgent_ack_item(uuid, text, jsonb) FROM public, anon;
GRANT EXECUTE ON FUNCTION public.urgent_ack_item(uuid, text, jsonb) TO authenticated;
