// Alphabet excludes 0/O/1/l/i so a printed id can't be misread letter-by-letter.
const ID_ALPHABET = '23456789ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghjkmnopqrstuvwxyz';

// Rejection sampling avoids modulo bias (256 isn't a multiple of the alphabet length).
export function randomToken(length) {
  const alphabetLen = ID_ALPHABET.length;
  const maxValid = 256 - (256 % alphabetLen);
  let out = '';
  const buf = new Uint8Array(length);
  while (out.length < length) {
    crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length && out.length < length; i++) {
      if (buf[i] < maxValid) out += ID_ALPHABET[buf[i] % alphabetLen];
    }
  }
  return out;
}

export async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Not a formal crypto guarantee, but avoids the obvious early-exit timing leak
// from `a === b` on a secret delete key, without needing nodejs_compat.
export function timingSafeEqual(a, b) {
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < maxLen; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

// A bare `word.Word` is far more often a missing space after a full stop than a
// link ("I miss you.Take care"), so matching any dot-separated pair rejects
// ordinary letters. Three narrower rules instead:
//   1. an explicit scheme or www. — unambiguous, case-insensitive
//   2. a known TLD, matched case-sensitively: real domains are written in
//      lowercase, while the false positives are all capitalised words
//   3. anything domain-shaped followed by a path
const SCHEME_LIKE = /(https?:\/\/|\bwww\.)/i;
const TLDS = 'com|net|org|io|co|me|ly|xyz|info|biz|shop|store|site|online|app|dev|ai|ru|cn|top|click|link|tv|cc|to|gg|vip|win';
const DOMAIN_LIKE = new RegExp('\\b[a-z0-9-]{1,63}\\.(?:' + TLDS + ')\\b');
const PATH_LIKE = /\b[a-z0-9-]{1,63}\.[a-z]{2,24}\/\S/i;
const LONG_DIGIT_RUN = /\d{8,}/;

function looksLikeLink(value) {
  return SCHEME_LIKE.test(value) || DOMAIN_LIKE.test(value) || PATH_LIKE.test(value);
}

export function findSpamReason(fields) {
  for (const [name, value] of Object.entries(fields)) {
    if (looksLikeLink(value)) {
      return `${name} looks like it contains a link, which isn't allowed on the wall.`;
    }
    if (LONG_DIGIT_RUN.test(value)) {
      return `${name} contains a long number, which isn't allowed on the wall.`;
    }
  }
  return null;
}

export function getIp(request) {
  return request.headers.get('CF-Connecting-IP') || '0.0.0.0';
}

// ALLOWED_ORIGIN is a comma-separated list so a custom domain can be added
// alongside the workers.dev one. Entries are trimmed and compared exactly:
// a substring or prefix test would let paperbloom.pages.dev.attacker.com through.
function allowedOrigins(env) {
  return (env.ALLOWED_ORIGIN || '').split(',').map(o => o.trim()).filter(Boolean);
}

// A request with no Origin header is not a cross-origin request: browsers omit
// Origin on same-origin GETs, which is exactly how the wall page calls this API.
// Only a *present* Origin has to match.
export function corsHeaders(request, env) {
  const origin = request.headers.get('Origin');
  const headers = { Vary: 'Origin' };
  if (origin && allowedOrigins(env).includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type';
  }
  return headers;
}

// No fallback: if the secret is missing, every ip_hash would be built from the
// literal string "undefined" — a known salt, which is worse than no hashing at
// all because it looks like it worked. Fail instead.
export function requireSalt(env) {
  if (!env.IP_SALT) {
    throw new Error('IP_SALT is not set; refusing to hash IPs against a known value.');
  }
  return env.IP_SALT;
}

export function json(status, data, request, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(request, env) }
  });
}
