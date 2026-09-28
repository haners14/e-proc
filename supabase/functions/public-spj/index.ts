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
    const adminAction = body?.action || (body?.spj_id && !body?.token && !body?.signature ? 'issue' : '')
    if (request.method === 'POST' && ['issue', 'initialize', 'recipients'].includes(adminAction)) {
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

      if (adminAction === 'recipients') {
        const spjId = String(body.spj_id || '')
        if (!spjId) return json({ error: 'SPJ wajib diisi' }, 400)
        const { data: recipients, error } = await admin.from('spj_header_recipients')
          .select('id,pencairan_item_id,nama_penerima,uraian,bank,no_rekening,subtotal,pph,total,tanda_tangan,status_ttd')
          .eq('spj_id', spjId).order('created_at', { ascending: true })
        if (error) return json({ error: 'Gagal memuat penerima' }, 500)
        return json({ recipients: recipients || [] })
      }

      if (adminAction === 'initialize') {
        const spjId = String(body.spj_id || '')
        if (!spjId) return json({ error: 'SPJ wajib diisi' }, 400)
        const { data: spj } = await admin.from('spj_headers').select('pencairan_id').eq('id', spjId).maybeSingle()
        if (!spj) return json({ error: 'Header SPJ tidak ditemukan' }, 404)
        const { data: sourceItems, error: sourceError } = await admin.from('pencairan_items')
          .select('id,nama_penerima,uraian,bank,no_rekening,subtotal,pph,total').eq('pencairan_id', spj.pencairan_id)
        if (sourceError || !sourceItems?.length) return json({ error: 'Penerima pencairan tidak tersedia' }, 400)
        const rows = sourceItems.map(item => ({
          spj_id: spjId, pencairan_item_id: String(item.id), nama_penerima: item.nama_penerima, uraian: item.uraian,
          bank: item.bank, no_rekening: item.no_rekening, subtotal: item.subtotal || 0,
          pph: item.pph || 0, total: item.total || 0, tanda_tangan: null, status_ttd: 'DRAFT', signed_at: null,
        }))
        const { error: copyError } = await admin.from('spj_header_recipients').upsert(rows, { onConflict: 'spj_id,pencairan_item_id', ignoreDuplicates: true })
        if (copyError) return json({ error: 'Gagal menyiapkan penerima SPJ' }, 500)
        return json({ ok: true, recipient_count: rows.length })
      }

      const spjId = String(body.spj_id || '')
      const itemId = String(body.pencairan_item_id || '')
      const scope = body.scope === 'shared' ? 'shared' : 'recipient'
      const hours = Math.min(Math.max(Number(body.expires_in_hours) || 24, 1), 24)
      if (!spjId || (scope === 'recipient' && !itemId)) return json({ error: 'SPJ dan penerima wajib dipilih' }, 400)

      const { data: spj } = await admin.from('spj_headers').select('id,pencairan_id').eq('id', spjId).maybeSingle()
      const { data: item } = itemId ? await admin.from('spj_header_recipients').select('spj_id,status_ttd').eq('id', itemId).maybeSingle() : { data: null }
      let { count: unsignedCount } = await admin.from('spj_header_recipients').select('id', { count: 'exact', head: true }).eq('spj_id', spjId).neq('status_ttd', 'SIGNED')
      // Header lama dibuat sebelum tabel penerima per-header tersedia. Siapkan salinan bersih saat pertama kali link dibuat.
      if (spj && !unsignedCount) {
        const { data: sourceItems } = await admin.from('pencairan_items')
          .select('id,nama_penerima,uraian,bank,no_rekening,subtotal,pph,total').eq('pencairan_id', spj.pencairan_id)
        if (sourceItems?.length) {
          await admin.from('spj_header_recipients').upsert(sourceItems.map(item => ({
            spj_id: spjId, pencairan_item_id: String(item.id), nama_penerima: item.nama_penerima, uraian: item.uraian,
            bank: item.bank, no_rekening: item.no_rekening, subtotal: item.subtotal || 0, pph: item.pph || 0,
            total: item.total || 0, tanda_tangan: null, status_ttd: 'DRAFT', signed_at: null,
          })), { onConflict: 'spj_id,pencairan_item_id', ignoreDuplicates: true })
          const retry = await admin.from('spj_header_recipients').select('id', { count: 'exact', head: true }).eq('spj_id', spjId).neq('status_ttd', 'SIGNED')
          unsignedCount = retry.count
        }
      }
      if (!spj || !unsignedCount || (scope === 'recipient' && (!item || String(spjId) !== String(item.spj_id) || item.status_ttd === 'SIGNED'))) {
        return json({ error: 'SPJ atau penerima tidak valid' }, 400)
      }

      const plainToken = randomToken()
      const { error: issueError } = await admin.from('spj_sign_tokens').insert({
        spj_id: spjId,
        pencairan_item_id: scope === 'shared' ? null : itemId,
        scope,
        token_hash: await sha256(plainToken),
        expires_at: new Date(Date.now() + hours * 60 * 60 * 1000).toISOString(),
        created_by: authData.user.id,
      })
      if (issueError) return json({ error: 'Gagal membuat tautan' }, 500)
      return json({
        url: `${allowedOrigin}/?token=${encodeURIComponent(plainToken)}`,
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
        .select('id,spj_id,pencairan_item_id,scope,expires_at,used_at,revoked_at')
        .eq('token_hash', tokenHash).maybeSingle()
      if (!tokenRow || (tokenRow.scope === 'recipient' && tokenRow.used_at) || tokenRow.revoked_at || new Date(tokenRow.expires_at) <= new Date()) {
        return json({ error: 'Tautan tidak valid atau kedaluwarsa' }, 404)
      }

      let items
      let error
      if (tokenRow.scope === 'shared') {
        const result = await admin.from('spj_header_recipients')
          .select('id,nama_penerima,bank,no_rekening,subtotal,pph,total,status_ttd')
          .eq('spj_id', tokenRow.spj_id)
        items = result.data
        error = result.error
      } else {
        const result = await admin.from('spj_header_recipients')
          .select('id,nama_penerima,bank,no_rekening,subtotal,pph,total,status_ttd')
          .eq('id', tokenRow.pencairan_item_id)
        items = result.data
        error = result.error
      }
      if (error || !items || (Array.isArray(items) && !items.length)) return json({ error: 'Data penerima tidak tersedia' }, 404)
      const list = Array.isArray(items) ? items : [items]
      return json({
        scope: tokenRow.scope,
        recipients: list.map(item => ({ id:item.id,name:item.nama_penerima,bank:item.bank||'-',account:maskedAccount(item.no_rekening),gross:item.subtotal||0,tax:item.pph||0,net:item.total||0,signed:item.status_ttd==='SIGNED' })),
        expires_at: tokenRow.expires_at,
      })
    }

    const signature = body?.signature
    const selectedItemId = String(body?.pencairan_item_id || '')
    if (typeof signature !== 'string' || !signature.startsWith('data:image/png;base64,') || signature.length > 350_000) {
      return json({ error: 'Format tanda tangan tidak valid' }, 400)
    }

    const { data: tokenRow } = await admin.from('spj_sign_tokens').select('id,spj_id,pencairan_item_id,scope,expires_at,used_at,revoked_at').eq('token_hash', tokenHash).maybeSingle()
    if (tokenRow?.scope === 'shared') {
      if (!selectedItemId || tokenRow.revoked_at || new Date(tokenRow.expires_at) <= new Date()) return json({ error: 'Tautan tidak valid atau kedaluwarsa' }, 409)
      const { data: item } = await admin.from('spj_header_recipients').select('spj_id,status_ttd').eq('id', selectedItemId).maybeSingle()
      if (!item || String(tokenRow.spj_id)!==String(item.spj_id) || item.status_ttd==='SIGNED') return json({ error: 'Penerima tidak dapat menandatangani' }, 409)
      const { error: submissionError } = await admin.from('spj_sign_submissions').insert({ token_id:tokenRow.id,pencairan_item_id:selectedItemId })
      if (submissionError) return json({ error: 'Penerima sudah menandatangani' }, 409)
      const { error: updateError } = await admin.from('spj_header_recipients').update({ tanda_tangan: signature, status_ttd: 'SIGNED', signed_at: new Date().toISOString() }).eq('id', selectedItemId)
      if (updateError) return json({ error: 'Tanda tangan gagal disimpan' }, 500)
      return json({ ok: true })
    }

    const { data: consumed, error: consumeError } = await admin.rpc('consume_spj_sign_token', { p_token_hash: tokenHash })
    const consumedToken = consumed?.[0]
    if (consumeError || !consumedToken) return json({ error: 'Tautan sudah digunakan, dicabut, atau kedaluwarsa' }, 409)

    const { error: updateError } = await admin.from('spj_header_recipients')
      .update({ tanda_tangan: signature, status_ttd: 'SIGNED', signed_at: new Date().toISOString() })
      .eq('id', consumedToken.pencairan_item_id)
    if (updateError) return json({ error: 'Tanda tangan gagal disimpan' }, 500)

    return json({ ok: true })
  } catch (error) {
    console.error(error)
    return json({ error: 'Terjadi gangguan layanan' }, 500)
  }
})
