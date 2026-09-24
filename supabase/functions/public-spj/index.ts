import { createClient } from 'npm:@supabase/supabase-js@2'

const allowedOrigin = 'https://bmd-eproc.vercel.app'
const corsHeaders = {
  'Access-Control-Allow-Origin': allowedOrigin,
  'Access-Control-Allow-Headers': 'authorization, apikey, content-type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Content-Type': 'application/json; charset=utf-8',
  'Vary': 'Origin',
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders })

async function sha256(value: string) {
  const data = new TextEncoder().encode(value)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function readSecretKey() {
  const keys = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') || '{}')
  if (!keys.default) throw new Error('Secret key Edge Function tidak tersedia')
  return keys.default
}

function readPublishableKey() {
  const keys = JSON.parse(Deno.env.get('SUPABASE_PUBLISHABLE_KEYS') || '{}')
  if (!keys.default) throw new Error('Publishable key Edge Function tidak tersedia')
  return keys.default
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

function maskedAccount(value: string | null) {
  const digits = String(value || '').replace(/\s/g, '')
  return digits ? `••••${digits.slice(-4)}` : '-'
}

Deno.serve(async (request) => {
  if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
  if (!['GET', 'POST'].includes(request.method)) return json({ error: 'Method tidak didukung' }, 405)

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!
    const admin = createClient(supabaseUrl, readSecretKey(), { auth: { persistSession: false } })
    const body = request.method === 'POST' ? await request.json() : null
    if (request.method === 'POST' && body?.action === 'issue') {
      const authorization = request.headers.get('Authorization') || ''
      const userClient = createClient(supabaseUrl, readPublishableKey(), {
        global: { headers: { Authorization: authorization } }, auth: { persistSession: false },
      })
      const { data: authData } = await userClient.auth.getUser()
      if (!authData.user) return json({ error: 'Login diperlukan' }, 401)

      const { data: issuer } = await admin.from('users')
        .select('role,active').eq('auth_user_id', authData.user.id).maybeSingle()
      if (!issuer?.active || !['Administrator', 'Staf Pengadaan'].includes(issuer.role)) {
        return json({ error: 'Hak akses tidak cukup' }, 403)
      }

      const spjId = String(body.spj_id || '')
      const itemId = String(body.pencairan_item_id || '')
      const hours = Math.min(Math.max(Number(body.expires_in_hours) || 24, 1), 24)
      if (!spjId || !itemId) return json({ error: 'SPJ dan penerima wajib dipilih' }, 400)

      const { data: spj } = await admin.from('spj_headers').select('pencairan_id').eq('id', spjId).maybeSingle()
      const { data: item } = await admin.from('pencairan_items').select('pencairan_id,status_ttd').eq('id', itemId).maybeSingle()
      if (!spj || !item || String(spj.pencairan_id) !== String(item.pencairan_id) || item.status_ttd === 'SIGNED') {
        return json({ error: 'SPJ atau penerima tidak valid' }, 400)
      }

      const plainToken = randomToken()
      const { error: issueError } = await admin.from('spj_sign_tokens').insert({
        spj_id: spjId,
        pencairan_item_id: itemId,
        token_hash: await sha256(plainToken),
        expires_at: new Date(Date.now() + hours * 60 * 60 * 1000).toISOString(),
        created_by: authData.user.id,
      })
      if (issueError) return json({ error: 'Gagal membuat tautan' }, 500)
      return json({
        url: `${supabaseUrl}/functions/v1/public-spj?token=${encodeURIComponent(plainToken)}`,
        expires_in_hours: hours,
      })
    }

    const token = request.method === 'GET'
      ? new URL(request.url).searchParams.get('token')
      : body?.token

    if (!token || typeof token !== 'string' || token.length < 32) return json({ error: 'Token tidak valid' }, 400)
    const tokenHash = await sha256(token)

    if (request.method === 'GET') {
      const { data: tokenRow } = await admin.from('spj_sign_tokens')
        .select('spj_id,pencairan_item_id,expires_at,used_at,revoked_at')
        .eq('token_hash', tokenHash).maybeSingle()
      if (!tokenRow || tokenRow.used_at || tokenRow.revoked_at || new Date(tokenRow.expires_at) <= new Date()) {
        return json({ error: 'Tautan tidak valid atau kedaluwarsa' }, 404)
      }

      const { data: item, error } = await admin.from('pencairan_items')
        .select('id,nama_penerima,bank,no_rekening,subtotal,pph,total,status_ttd')
        .eq('id', tokenRow.pencairan_item_id).single()
      if (error || !item) return json({ error: 'Data penerima tidak tersedia' }, 404)
      return json({
        recipient: {
          name: item.nama_penerima,
          bank: item.bank || '-',
          account: maskedAccount(item.no_rekening),
          gross: item.subtotal || 0,
          tax: item.pph || 0,
          net: item.total || 0,
        },
        expires_at: tokenRow.expires_at,
      })
    }

    const signature = body?.signature
    if (typeof signature !== 'string' || !signature.startsWith('data:image/png;base64,') || signature.length > 350_000) {
      return json({ error: 'Format tanda tangan tidak valid' }, 400)
    }

    const { data: consumed, error: consumeError } = await admin.rpc('consume_spj_sign_token', { p_token_hash: tokenHash })
    const consumedToken = consumed?.[0]
    if (consumeError || !consumedToken) return json({ error: 'Tautan sudah digunakan, dicabut, atau kedaluwarsa' }, 409)

    const { error: updateError } = await admin.from('pencairan_items')
      .update({ tanda_tangan: signature, status_ttd: 'SIGNED' })
      .eq('id', consumedToken.pencairan_item_id)
    if (updateError) return json({ error: 'Tanda tangan gagal disimpan' }, 500)

    return json({ ok: true })
  } catch (error) {
    console.error(error)
    return json({ error: 'Terjadi gangguan layanan' }, 500)
  }
})
