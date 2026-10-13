import { createClient } from 'npm:@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, apikey, x-client-info, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json; charset=utf-8',
}

function reply(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders })
}

function normalizeUsername(input: unknown): string {
  const value = String(input ?? '').trim().toLowerCase()
  const points = Array.from(value).length
  if (points < 3 || points > 32 || !/^[\p{L}\p{N}._-]+$/u.test(value)) {
    throw new Error('اسم المستخدم يجب أن يكون من 3 إلى 32 حرفاً أو رقماً، ويمكن استخدام النقطة والشرطة فقط.')
  }
  return value
}

function validatePassword(input: unknown): string {
  const value = String(input ?? '')
  if (value.length < 8 || value.length > 128) {
    throw new Error('كلمة المرور يجب أن تكون بين 8 و128 خانة.')
  }
  return value
}

async function authAlias(username: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(username)))
  const hex = Array.from(digest.slice(0, 20)).map((n) => n.toString(16).padStart(2, '0')).join('')
  return `ua-${hex}@login.urgent.invalid`
}

function projectKeys() {
  const url = Deno.env.get('SUPABASE_URL')
  const publishableKeys = Deno.env.get('SUPABASE_PUBLISHABLE_KEYS')
  let publishable = Deno.env.get('SUPABASE_ANON_KEY')
  if (publishableKeys) {
    try { publishable = JSON.parse(publishableKeys).default || publishable } catch { /* use legacy publishable key */ }
  }
  let serviceRole = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
  const secretKeys = Deno.env.get('SUPABASE_SECRET_KEYS')
  if (secretKeys) {
    try { serviceRole = JSON.parse(secretKeys).default || serviceRole } catch { /* use injected legacy service-role key */ }
  }
  if (!url || !publishable || !serviceRole) throw new Error('Supabase Edge Function environment is incomplete.')
  return { url, publishable, serviceRole }
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
  if (req.method !== 'POST') return reply(405, { error: 'الطريقة غير مدعومة.' })
  const length = Number(req.headers.get('content-length') || 0)
  if (length > 16000) return reply(413, { error: 'حجم الطلب أكبر من المسموح.' })

  try {
    const authHeader = req.headers.get('authorization') || ''
    const match = authHeader.match(/^Bearer\s+(.+)$/i)
    if (!match) return reply(401, { error: 'يلزم تسجيل دخول مسؤول.' })

    const body = await req.json().catch(() => null) as Record<string, unknown> | null
    if (!body || typeof body !== 'object') return reply(400, { error: 'بيانات الطلب غير صالحة.' })
    const roomId = String(body.roomId || '')
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(roomId)) {
      return reply(400, { error: 'معرّف الغرفة غير صالح.' })
    }

    const { url, publishable, serviceRole } = projectKeys()
    const userClient = createClient(url, publishable, {
      auth: { persistSession: false, autoRefreshToken: false },
      global: { headers: { Authorization: `Bearer ${match[1]}` } },
    })
    const { data: authData, error: authError } = await userClient.auth.getUser(match[1])
    if (authError || !authData.user) return reply(401, { error: 'انتهت الجلسة؛ سجّل الدخول مجدداً.' })

    const { data: membership, error: membershipError } = await userClient
      .from('room_members').select('role').eq('room_id', roomId).eq('user_id', authData.user.id).maybeSingle()
    if (membershipError || !membership || membership.role !== 'admin') {
      return reply(403, { error: 'إدارة الحسابات متاحة للمسؤول فقط.' })
    }

    const adminClient = createClient(url, serviceRole, {
      auth: { persistSession: false, autoRefreshToken: false },
    })
    const action = String(body.action || '')

    if (action === 'create_user') {
      let username: string
      let password: string
      try {
        username = normalizeUsername(body.username)
        password = validatePassword(body.password)
      } catch (error) {
        return reply(400, { error: error instanceof Error ? error.message : 'بيانات الحساب غير صالحة.' })
      }
      const role = String(body.role || 'reader')
      if (!['admin', 'editor', 'operator', 'reader'].includes(role)) {
        return reply(400, { error: 'الصلاحية المحددة غير صالحة.' })
      }
      const displayName = String(body.displayName || username).trim().slice(0, 80) || username
      const email = await authAlias(username)
      const { data: created, error: createError } = await adminClient.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: { username },
      })
      if (createError || !created.user) {
        console.error('manage-users: create Auth account failed', createError?.code || createError?.status || 'unknown')
        return reply(409, { error: 'اسم المستخدم موجود مسبقاً أو تعذّر إنشاء الحساب.' })
      }

      const { error: rpcError } = await userClient.rpc('urgent_set_member', {
        p_room: roomId,
        p_username: username,
        p_role: role,
        p_display_name: displayName,
        p_can_view_bar: body.canViewBar === true,
        p_user: created.user.id,
      })
      if (rpcError) {
        const { error: cleanupError } = await adminClient.auth.admin.deleteUser(created.user.id)
        if (cleanupError) console.error('manage-users: rollback of unassigned account failed', cleanupError.code || 'unknown')
        console.error('manage-users: membership RPC failed', rpcError.code || 'unknown')
        return reply(rpcError.code === '42501' ? 403 : 400, { error: 'تعذّر حفظ عضوية المستخدم. تحقّق من الاسم والصلاحيات ثم أعد المحاولة.' })
      }
      return reply(201, { ok: true, username })
    }

    if (action === 'set_password') {
      const userId = String(body.userId || '')
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(userId)) {
        return reply(400, { error: 'معرّف المستخدم غير صالح.' })
      }
      let password: string
      try { password = validatePassword(body.password) } catch (error) {
        return reply(400, { error: error instanceof Error ? error.message : 'كلمة المرور غير صالحة.' })
      }
      const { data: target, error: targetError } = await adminClient.from('room_members')
        .select('user_id').eq('room_id', roomId).eq('user_id', userId).maybeSingle()
      if (targetError || !target) return reply(404, { error: 'المستخدم غير موجود في هذه الغرفة.' })
      const { error: updateError } = await adminClient.auth.admin.updateUserById(userId, { password })
      if (updateError) {
        console.error('manage-users: password update failed', updateError.code || updateError.status || 'unknown')
        return reply(400, { error: 'تعذّر تحديث كلمة المرور.' })
      }
      return reply(200, { ok: true })
    }

    return reply(400, { error: 'الإجراء غير معروف.' })
  } catch (error) {
    console.error('manage-users: request failed', error instanceof Error ? error.message : 'unknown')
    return reply(500, { error: 'حدث خطأ داخلي؛ لم تُعرض أي مفاتيح أو كلمات مرور.' })
  }
})
