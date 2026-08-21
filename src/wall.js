import { randomToken, sha256Hex, timingSafeEqual, findSpamReason, getIp, requireSalt, json } from './util.js';

// Must stay in sync with the FLOWERS table in index.html. Kept as a plain
// list here (not imported) because the client bundle is a single static
// HTML file with no build step.
const FLOWER_KEYS = ['hibiscus', 'sakura', 'plumeria', 'daisy', 'lotus', 'marigold'];

const ID_LENGTH = 10;
const DELETE_KEY_LENGTH = 24;
const POST_LIMIT_PER_HOUR = 5;
const REPORT_LIMIT_PER_HOUR = 20;
const PAGE_SIZE = 12;
const HOUR_MS = 60 * 60 * 1000;

function clampString(value, max) {
  return typeof value === 'string' ? value.trim().slice(0, max) : null;
}

export async function createLetter(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json(400, { error: 'invalid_body', message: 'Request body must be JSON.' }, request, env);
  }
  if (!body || typeof body !== 'object') {
    return json(400, { error: 'invalid_body', message: 'Request body must be JSON.' }, request, env);
  }

  const opening = clampString(body.opening, 40);
  const bodyText = clampString(body.body, 500);
  const signature = clampString(body.signature, 40);
  const flower = typeof body.flower === 'string' ? body.flower : null;

  if (opening === null || bodyText === null || signature === null) {
    return json(400, { error: 'missing_fields', message: 'opening, body, and signature must all be strings.' }, request, env);
  }
  if (!bodyText) {
    return json(400, { error: 'empty_body', message: 'body cannot be empty.' }, request, env);
  }
  if (!flower || !FLOWER_KEYS.includes(flower)) {
    return json(400, { error: 'invalid_flower', message: 'flower must be one of: ' + FLOWER_KEYS.join(', ') }, request, env);
  }

  const spamReason = findSpamReason({ opening, body: bodyText, signature });
  if (spamReason) {
    return json(400, { error: 'spam_rejected', message: spamReason }, request, env);
  }

  const ipHash = await sha256Hex(getIp(request) + requireSalt(env));
  const hourAgo = Date.now() - HOUR_MS;
  // Counted from the append-only log, not from `wall`: DELETE is a hard delete,
  // so counting live rows let an author post, delete, and post again forever.
  const rate = await env.DB
    .prepare('SELECT COUNT(*) AS n FROM wall_post_log WHERE ip_hash = ? AND created_at > ?')
    .bind(ipHash, hourAgo)
    .first();
  if (rate.n >= POST_LIMIT_PER_HOUR) {
    return json(429, { error: 'rate_limited', message: 'Too many letters posted from this connection in the last hour. Try again later.' }, request, env);
  }

  const deleteKey = randomToken(DELETE_KEY_LENGTH);
  const createdAt = Date.now();

  let id;
  let inserted = false;
  for (let attempt = 0; attempt < 5 && !inserted; attempt++) {
    id = randomToken(ID_LENGTH);
    try {
      await env.DB
        .prepare(
          `INSERT INTO wall (id, opening, body, signature, flower, created_at, delete_key, visible, reports, ip_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?)`
        )
        .bind(id, opening, bodyText, signature, flower, createdAt, deleteKey, ipHash)
        .run();
      inserted = true;
    } catch (err) {
      if (attempt === 4) throw err;
    }
  }

  await env.DB
    .prepare('INSERT INTO wall_post_log (ip_hash, created_at) VALUES (?, ?)')
    .bind(ipHash, createdAt)
    .run();

  return json(201, { id, deleteKey }, request, env);
}

function encodeCursor(createdAt, id) {
  const bin = `${createdAt}:${id}`;
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeCursor(cursor) {
  try {
    const b64 = cursor.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
    const [createdAtStr, id] = atob(b64 + pad).split(':');
    const createdAt = Number(createdAtStr);
    if (!Number.isFinite(createdAt) || !id) return null;
    return { createdAt, id };
  } catch {
    return null;
  }
}

export async function listLetters(request, env) {
  const url = new URL(request.url);

  const requested = parseInt(url.searchParams.get('limit') || '', 10);
  const limit = Number.isFinite(requested) && requested > 0 ? Math.min(requested, PAGE_SIZE) : PAGE_SIZE;

  const cursorParam = url.searchParams.get('cursor');
  const cursor = cursorParam ? decodeCursor(cursorParam) : null;

  const columns = 'id, opening, body, signature, flower, created_at';
  let stmt;
  if (cursor) {
    stmt = env.DB
      .prepare(
        `SELECT ${columns} FROM wall
         WHERE visible = 1 AND (created_at < ?1 OR (created_at = ?1 AND id < ?2))
         ORDER BY created_at DESC, id DESC LIMIT ?3`
      )
      .bind(cursor.createdAt, cursor.id, limit + 1);
  } else {
    stmt = env.DB
      .prepare(`SELECT ${columns} FROM wall WHERE visible = 1 ORDER BY created_at DESC, id DESC LIMIT ?1`)
      .bind(limit + 1);
  }

  const { results } = await stmt.all();

  let letters = results;
  let nextCursor = null;
  if (results.length > limit) {
    letters = results.slice(0, limit);
    const last = letters[letters.length - 1];
    nextCursor = encodeCursor(last.created_at, last.id);
  }

  return json(200, { letters, nextCursor }, request, env);
}

export async function reportLetter(request, env, id) {
  const ipHash = await sha256Hex(getIp(request) + requireSalt(env));
  const hourAgo = Date.now() - HOUR_MS;

  const rate = await env.DB
    .prepare('SELECT COUNT(*) AS n FROM wall_report_log WHERE ip_hash = ? AND created_at > ?')
    .bind(ipHash, hourAgo)
    .first();
  if (rate.n >= REPORT_LIMIT_PER_HOUR) {
    return json(429, { error: 'rate_limited', message: 'Too many reports from this connection in the last hour. Try again later.' }, request, env);
  }

  // Claim the (letter, reporter) pair first. The unique index makes this the
  // dedupe check and closes the race between two concurrent reports, so one
  // person can no longer reach the auto-hide threshold of 2 on their own.
  const claim = await env.DB
    .prepare('INSERT OR IGNORE INTO wall_report_log (letter_id, ip_hash, created_at) VALUES (?, ?, ?)')
    .bind(id, ipHash, Date.now())
    .run();

  if (!claim.meta.changes) {
    // Already reported by this ip_hash. Answer the same way as a first report
    // so the response can't be used to probe who has reported what.
    return json(200, { ok: true }, request, env);
  }

  const result = await env.DB
    .prepare(
      `UPDATE wall
       SET reports = reports + 1,
           visible = CASE WHEN reports + 1 >= 2 THEN 0 ELSE visible END
       WHERE id = ?
       RETURNING visible`
    )
    .bind(id)
    .first();

  if (!result) {
    // No such letter: drop the claim so a typo'd id can't burn a real one.
    await env.DB.prepare('DELETE FROM wall_report_log WHERE letter_id = ? AND ip_hash = ?').bind(id, ipHash).run();
    return json(404, { error: 'not_found' }, request, env);
  }

  return json(200, { ok: true, visible: !!result.visible }, request, env);
}

export async function deleteLetter(request, env, id) {
  let body;
  try {
    body = await request.json();
  } catch {
    body = null;
  }
  const deleteKey = body && typeof body.deleteKey === 'string' ? body.deleteKey : null;
  if (!deleteKey) {
    return json(400, { error: 'missing_delete_key', message: 'deleteKey is required.' }, request, env);
  }

  const row = await env.DB.prepare('SELECT delete_key FROM wall WHERE id = ?').bind(id).first();
  if (!row) {
    return json(404, { error: 'not_found' }, request, env);
  }
  if (!timingSafeEqual(deleteKey, row.delete_key)) {
    return json(403, { error: 'invalid_delete_key', message: 'That delete key is not correct.' }, request, env);
  }

  await env.DB.prepare('DELETE FROM wall WHERE id = ?').bind(id).run();
  return json(200, { ok: true }, request, env);
}
