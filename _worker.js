// ============================================================
// VELZAR SCRIPTS - Proteccion de codigo fuente (sin keys manuales)
// Cloudflare Pages (Advanced Mode) - reemplaza tu _worker.js
// Requiere 1 KV namespace bindeado: VELZAR_DB
// Requiere 1 variable de entorno secreta: ADMIN_SECRET
//
// Como funciona:
// - El loadstring se comparte libre, no hay keys que pedir ni pegar.
// - El .lua publico es solo un stub: pide el codigo real al Worker.
// - El Worker identifica al usuario por HWID automaticamente (primera
//   vez que corre, queda registrado) y le entrega el codigo cifrado
//   con un token que vence en segundos y se usa una sola vez.
// - El codigo real nunca esta en GitHub ni se sirve como archivo estatico.
// - Si alguien filtra un script, la marca de agua te dice que HWID fue,
//   y lo podes banear sin tocar nada del repo.
// ============================================================

// Nombre publico del script -> id interno en KV donde esta el codigo real
const PROTECTED_SCRIPTS = {
  "otc": "code:otc",
  "sexyboy-esp": "code:sexyboy-esp",
  "blockcopysb": "code:blockcopysb",
  "test": "code:test",
};

function randomId(bytes = 16) {
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

// ---- RC4: cifrado simetrico, facil de replicar en Lua puro ----
function rc4(bytes, keyStr) {
  const key = new TextEncoder().encode(keyStr);
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i] + key[i % key.length]) & 0xff;
    [S[i], S[j]] = [S[j], S[i]];
  }
  const out = new Uint8Array(bytes.length);
  let i = 0;
  j = 0;
  for (let n = 0; n < bytes.length; n++) {
    i = (i + 1) & 0xff;
    j = (j + S[i]) & 0xff;
    [S[i], S[j]] = [S[j], S[i]];
    const k = S[(S[i] + S[j]) & 0xff];
    out[n] = bytes[n] ^ k;
  }
  return out;
}

function rc4Encrypt(plainText, keySeed) {
  const plainBytes = new TextEncoder().encode(plainText);
  const outBytes = rc4(plainBytes, keySeed);
  let bin = "";
  outBytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

// -------------------- Handlers --------------------

// POST /api/auth  { hwid, script }
// No pide key. Si el HWID es nuevo, lo registra solo. Si esta baneado, corta.
async function handleAuth(request, env) {
  if (request.method !== "POST") return jsonResponse({ error: "method" }, 405);

  const body = await request.json().catch(() => null);
  const { hwid, script } = body || {};
  if (!hwid || !script) return jsonResponse({ error: "missing_fields" }, 400);
  if (!PROTECTED_SCRIPTS[script]) return jsonResponse({ error: "unknown_script" }, 404);

  let record = await env.VELZAR_DB.get("hwid:" + hwid, { type: "json" });
  if (!record) {
    record = { createdAt: Date.now(), banned: false };
    await env.VELZAR_DB.put("hwid:" + hwid, JSON.stringify(record));
  }
  if (record.banned) return jsonResponse({ error: "banned" }, 403);

  // Rate limit: max 1 pedido cada 2 segundos por HWID.
  // Cloudflare KV no permite expirationTtl menor a 60s, asi que
  // controlamos el tiempo a mano con una marca de tiempo guardada.
  const now = Date.now();
  const rlRaw = await env.VELZAR_DB.get("rl:" + hwid, { type: "json" });
  if (rlRaw && now - rlRaw.last < 2000) {
    return jsonResponse({ error: "rate_limited" }, 429);
  }
  await env.VELZAR_DB.put("rl:" + hwid, JSON.stringify({ last: now }), { expirationTtl: 60 });

  // Token de un solo uso, vence en 20 segundos (chequeado a mano en /api/payload,
  // el expirationTtl de 60s es solo limpieza de KV, no el vencimiento real).
  const token = randomId(24);
  await env.VELZAR_DB.put(
    "tok:" + token,
    JSON.stringify({ script, hwid, used: false, createdAt: now }),
    { expirationTtl: 60 }
  );

  return jsonResponse({ token });
}

// GET /api/payload?t=TOKEN
async function handlePayload(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get("t");
  if (!token) return jsonResponse({ error: "missing_token" }, 400);

  const raw = await env.VELZAR_DB.get("tok:" + token);
  if (!raw) return jsonResponse({ error: "invalid_or_expired_token" }, 401);
  await env.VELZAR_DB.delete("tok:" + token); // un solo uso, se borra ya

  const data = JSON.parse(raw);
  if (Date.now() - data.createdAt > 20000) {
    return jsonResponse({ error: "token_expired" }, 401);
  }
  const kvId = PROTECTED_SCRIPTS[data.script];
  const sourceCode = await env.VELZAR_DB.get(kvId);
  if (!sourceCode) return jsonResponse({ error: "script_not_configured" }, 404);

  // Marca de agua: queda el HWID y el token en un comentario al principio.
  const watermark = `-- wm:${data.hwid.slice(0, 12)}:${token.slice(0, 8)}\n`;
  const encrypted = rc4Encrypt(watermark + sourceCode, token);

  return jsonResponse({ payload: encrypted });
}

// -------------------- Admin --------------------
function checkAdmin(request, env) {
  const auth = request.headers.get("Authorization") || "";
  return !!env.ADMIN_SECRET && auth === "Bearer " + env.ADMIN_SECRET;
}

// POST /api/admin/script  { script, source }  -> sube/actualiza el codigo real
async function handleAdminScript(request, env) {
  if (!checkAdmin(request, env)) return jsonResponse({ error: "unauthorized" }, 401);
  const { script, source } = await request.json().catch(() => ({}));
  if (!script || !PROTECTED_SCRIPTS[script] || !source) {
    return jsonResponse({ error: "bad_request" }, 400);
  }
  await env.VELZAR_DB.put(PROTECTED_SCRIPTS[script], source);
  return jsonResponse({ ok: true });
}

// POST /api/admin/ban  { hwid, banned: true|false }  -> banear/desbanear un HWID
async function handleAdminBan(request, env) {
  if (!checkAdmin(request, env)) return jsonResponse({ error: "unauthorized" }, 401);
  const { hwid, banned } = await request.json().catch(() => ({}));
  if (!hwid) return jsonResponse({ error: "missing_hwid" }, 400);
  let record = (await env.VELZAR_DB.get("hwid:" + hwid, { type: "json" })) || { createdAt: Date.now() };
  record.banned = !!banned;
  await env.VELZAR_DB.put("hwid:" + hwid, JSON.stringify(record));
  return jsonResponse({ ok: true, record });
}

// -------------------- Router --------------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.toLowerCase();

    if (path === "/api/auth") return handleAuth(request, env);
    if (path === "/api/payload") return handlePayload(request, env);
    if (path === "/api/admin/script") return handleAdminScript(request, env);
    if (path === "/api/admin/ban") return handleAdminBan(request, env);

    // ---- tu logica original para servir los .lua y la pagina HTML ----

    const validScripts = ["/test.lua", "/sexyboy-esp.lua", "/blockcopysb.lua", "/otc.lua"];

    if (/\.lua$/i.test(path) && !validScripts.includes(path)) {
      return Response.redirect("https://boytest49.pages.dev/", 302);
    }

    if (validScripts.includes(path)) {
      const accept = request.headers.get("Accept") || "";
      const fetchMode = request.headers.get("Sec-Fetch-Mode") || "";
      const isBrowserNavigation = fetchMode === "navigate" || accept.includes("text/html");

      if (isBrowserNavigation) {
        const loader = `loadstring(game:HttpGet("${url.origin}${url.pathname}"))()`;
        const safeLoader = loader
          .replace(/&/g, "&amp;").replace(/</g, "&lt;")
          .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

        const html = `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Velzar Scripts</title>
<style>
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;padding:24px;
  display:flex;align-items:center;justify-content:center;
  background:#050505;color:#f5f5f5;
  font-family:Arial,sans-serif
}
.container{width:100%;max-width:560px}
.brand{
  margin-bottom:18px;text-align:center;
  font-size:22px;font-weight:800;letter-spacing:3px
}
.brand span{color:#a855f7}
.subtitle{
  margin:0 0 22px;text-align:center;
  color:#777;font-size:13px
}
.code-card{
  overflow:hidden;border:1px solid #29202f;
  border-radius:16px;background:#0d0d10;
  box-shadow:0 0 28px #a855f714
}
.card-header{
  display:flex;align-items:center;gap:7px;
  padding:14px 16px;border-bottom:1px solid #242027;
  color:#999;font-size:12px
}
.dot{width:8px;height:8px;border-radius:50%;background:#a855f7}
pre{
  margin:0;padding:22px 18px;overflow-wrap:anywhere;
  white-space:pre-wrap;color:#d8b4fe;
  font:13px/1.8 Consolas,monospace
}
.card-footer{display:flex;justify-content:center;padding:0 16px 16px}
.copy-button{
  display:flex;align-items:center;justify-content:center;gap:9px;
  min-width:150px;padding:10px 16px;
  border:1px solid #3b2a49;border-radius:10px;
  background:#17121d;color:#eee;font-size:13px;cursor:pointer
}
.copy-button:hover{background:#251630;border-color:#a855f7}
.copy-button svg{
  width:17px;height:17px;fill:none;stroke:currentColor;
  stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round
}
.copy-button.copied{color:#d8b4fe;border-color:#a855f7}
.footer-text{
  margin-top:18px;text-align:center;color:#555;
  font-size:11px;letter-spacing:1px
}
</style>
</head>
<body>
<main class="container">
  <div class="brand">VELZAR <span>SCRIPTS</span></div>
  <p class="subtitle">Script access</p>
  <section class="code-card">
    <div class="card-header"><span class="dot"></span><span>LOADSTRING</span></div>
    <pre id="loader">${safeLoader}</pre>
    <div class="card-footer">
      <button class="copy-button" id="copyButton" type="button">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <rect x="8" y="8" width="12" height="12" rx="2"></rect>
          <path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"></path>
        </svg>
        <span id="copyLabel">Copiar script</span>
      </button>
    </div>
  </section>
  <div class="footer-text">VELZAR SCRIPTS · OFFICIAL</div>
</main>
<script>
const loader = ${JSON.stringify(loader)};
const button = document.getElementById("copyButton");
const label = document.getElementById("copyLabel");

button.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(loader);
    label.textContent = "¡Copiado!";
    button.classList.add("copied");
  } catch (error) {
    const area = document.createElement("textarea");
    area.value = loader;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    const success = document.execCommand("copy");
    area.remove();
    label.textContent = success ? "¡Copiado!" : "No se pudo copiar";
    if (success) button.classList.add("copied");
  }

  setTimeout(() => {
    label.textContent = "Copiar script";
    button.classList.remove("copied");
  }, 1800);
});
</script>
</body>
</html>`;

        return new Response(request.method === "HEAD" ? null : html, {
          status: 200,
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
          },
        });
      }

      // El executor (o quien se haga pasar por uno) recibe solo el stub.
      return env.ASSETS.fetch(request);
    }

    return env.ASSETS.fetch(request);
  },
};
