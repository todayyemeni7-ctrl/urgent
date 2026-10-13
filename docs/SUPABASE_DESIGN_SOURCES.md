# References for the Supabase integration

The following official Supabase documentation informed the schema, role policies, authentication, and Realtime design:

- [Realtime Postgres Changes](https://supabase.com/docs/guides/realtime/postgres-changes) — database change feeds and their delivery model.
- [Realtime Authorization](https://supabase.com/docs/guides/realtime/authorization) — authorization of private Realtime channels.
- [Subscribing to database changes](https://supabase.com/docs/guides/realtime/subscribing-to-database-changes) — client subscription patterns and limitations.
- [Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security) — policies based on `auth.uid()` and least-privilege table access.
- [JavaScript password sign-in](https://supabase.com/docs/reference/javascript/auth-signinwithpassword) — browser login using Supabase Auth.
- [Supabase JavaScript client](https://supabase.com/docs/reference/javascript/introduction) — browser SDK initialization and client API.

Implementation notes: the database uses room-scoped membership checks and RLS; the browser must use a publishable/anon key only; private Realtime topics require membership authorization; service-role/secret keys must remain server-side and are never needed by the browser.
