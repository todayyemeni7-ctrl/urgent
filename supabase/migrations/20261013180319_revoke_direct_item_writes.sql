-- All content changes must pass through role-checking SECURITY DEFINER RPCs.
-- This prevents editors from directly changing acknowledgement/pin or metadata columns.
revoke insert, update on public.urgent_items from authenticated;
