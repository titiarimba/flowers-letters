import { createLetter, listLetters, reportLetter, deleteLetter } from './wall.js';
import { corsHeaders, json } from './util.js';

const REPORT_PATH = /^\/api\/wall\/([^/]+)\/report$/;
const ID_PATH = /^\/api\/wall\/([^/]+)$/;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Everything else is a static file; run_worker_first only forces /api/*
    // through this Worker, so this branch only ever sees non-API requests.
    if (!url.pathname.startsWith('/api/')) {
      return env.ASSETS.fetch(request);
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }

    try {
      if (url.pathname === '/api/wall') {
        if (request.method === 'POST') return await createLetter(request, env);
        if (request.method === 'GET') return await listLetters(request, env);
      }

      const reportMatch = url.pathname.match(REPORT_PATH);
      if (reportMatch && request.method === 'POST') {
        return await reportLetter(request, env, reportMatch[1]);
      }

      const idMatch = url.pathname.match(ID_PATH);
      if (idMatch && request.method === 'DELETE') {
        return await deleteLetter(request, env, idMatch[1]);
      }
    } catch (err) {
      console.error(err);
      return json(500, { error: 'internal_error', message: 'Something went wrong.' }, request, env);
    }

    return json(404, { error: 'not_found' }, request, env);
  }
};
