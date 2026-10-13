# References for the Supabase integration

The following official Supabase documentation informed the schema, role policies, authentication, and Realtime design:

- [Realtime Postgres Changes](https://supabase.com/docs/guides/realtime/postgres-changes) — database change feeds and their delivery model.
- [Realtime Authorization](https://supabase.com/docs/guides/realtime/authorization) — authorization of private Realtime channels.
- [Subscribing to database changes](https://supabase.com/docs/guides/realtime/subscribing-to-database-changes) — client subscription patterns and limitations.
- [Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security) — policies based on `auth.uid()` and least-privilege table access.
- [JavaScript password sign-in](https://supabase.com/docs/reference/javascript/auth-signinwithpassword) — browser login using Supabase Auth.
- [Supabase JavaScript client](https://supabase.com/docs/reference/javascript/introduction) — browser SDK initialization and client API.

Implementation notes: the database uses room-scoped membership checks and RLS; the browser must use a publishable/anon key only; private Realtime topics require membership authorization; service-role/secret keys must remain server-side and are never needed by the browser.


## إدارة حسابات المستخدمين بأسماء دخول ووظائف خلفية — 2026-10-13

- Edge Functions تستطيع تمرير رمز `Authorization` الوارد إلى عميل Supabase للتحقق من المستخدم مع استمرار تطبيق RLS.
- بيئة Edge Functions توفر مفاتيح المشروع عبر متغيرات البيئة؛ مفاتيح `service_role`/`secret` تتجاوز RLS وتبقى في الخادم فقط، ولا تُضمّن في الواجهة أو Git.
- إنشاء المستخدم الإداري يتم من خلفية موثوقة عبر Supabase Auth Admin API؛ لا يحفظ التطبيق كلمة المرور كنص صريح.

المراجع الرسمية التي فُتحت وراجعت:
- https://supabase.com/docs/guides/functions/auth-legacy-jwt — ربط Edge Functions بـAuth وRLS.
- https://supabase.com/docs/guides/functions/secrets — أسرار البيئة الافتراضية ومنع وضع المفاتيح السرية في المتصفح أو المستودع.
- https://supabase.com/docs/guides/getting-started/migrating-to-new-api-keys — الفرق بين publishable وsecret ومكان استخدامهما.
- https://supabase.com/docs/reference/javascript/auth-admin-createuser — إنشاء المستخدم إدارياً.
