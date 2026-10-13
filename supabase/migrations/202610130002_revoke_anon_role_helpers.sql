-- Supabase projects can grant EXECUTE on newly created public functions by default.
-- Ensure anonymous callers cannot probe membership/role helpers.
revoke all on function public.urgent_is_member(uuid) from anon;
revoke all on function public.urgent_has_role(uuid, text[]) from anon;
